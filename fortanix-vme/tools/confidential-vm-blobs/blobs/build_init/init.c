/*
 * MIT License
 *
 * Copyright 2020 Amazon.com, Inc. or its affiliates. All Rights Reserved.
 * Code from OpenGCS (https://github.com/microsoft/opengcs) is used in this file.
 *
 * Copyright (c) Microsoft Corporation. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 *
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <linux/vm_sockets.h>
#include <poll.h>

_Noreturn void die(const char *msg);
#define die_on(CONDITION, ...) \
    do { \
        if (CONDITION) { \
            die(__VA_ARGS__); \
        } \
    } while (0)

#define DEFAULT_PATH_ENV "PATH=/sbin:/usr/sbin:/bin:/usr/bin"
#define TIMEOUT 20000 // millis

const char *const default_envp[] = {
    DEFAULT_PATH_ENV,
    NULL,
};

const char *const default_argv[] = { "sh", NULL };

struct Mount {
    const char *source, *target, *type;
    unsigned long flags;
    const void *data;
};

struct Mkdir {
    const char *path;
    mode_t mode;
};

struct Mknod {
    const char *path;
    mode_t mode;
    int major, minor;
};

struct Symlink {
    const char *linkpath, *target;
};

enum OpType {
    OpMount,
    OpMkdir,
    OpMknod,
    OpSymlink,
};

struct InitOp {
    enum OpType op;
    union {
        struct Mount mount;
        struct Mkdir mkdir;
        struct Mknod mknod;
        struct Symlink symlink;
    };
};

const struct InitOp ops[] = {
    // mount /proc (which should already exist)
    { OpMount, .mount = { "proc", "/proc", "proc", MS_NODEV | MS_NOSUID | MS_NOEXEC } },

    // add symlinks in /dev (which is already mounted)
    { OpSymlink, .symlink = { "/dev/fd", "/proc/self/fd" } },
    { OpSymlink, .symlink = { "/dev/stdin", "/proc/self/fd/0" } },
    { OpSymlink, .symlink = { "/dev/stdout", "/proc/self/fd/1" } },
    { OpSymlink, .symlink = { "/dev/stderr", "/proc/self/fd/2" } },

    // mount tmpfs on /run and /tmp (which should already exist)
    { OpMount, .mount = { "tmpfs", "/run", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, "mode=0755" } },
    { OpMount, .mount = { "tmpfs", "/tmp", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC } },

    // mount shm and devpts
    { OpMkdir, .mkdir = { "/dev/shm", 0755 } },
    { OpMount, .mount = { "shm", "/dev/shm", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC } },
    { OpMkdir, .mkdir = { "/dev/pts", 0755 } },
    { OpMount, .mount = { "devpts", "/dev/pts", "devpts", MS_NOSUID | MS_NOEXEC } },

    // mount /sys (which should already exist)
    { OpMount, .mount = { "sysfs", "/sys", "sysfs", MS_NODEV | MS_NOSUID | MS_NOEXEC } },
    { OpMount, .mount = { "cgroup_root", "/sys/fs/cgroup", "tmpfs", MS_NODEV | MS_NOSUID | MS_NOEXEC, "mode=0755" } },
};

void warn(const char *msg) {
    int error = errno;
    perror(msg);
    errno = error;
}

void warn2(const char *msg1, const char *msg2) {
    int error = errno;
    fputs(msg1, stderr);
    fputs(": ", stderr);
    errno = error;
    warn(msg2);
}

_Noreturn void dien() {
    exit(errno);
}

_Noreturn void die(const char *msg) {
    warn(msg);
    dien();
}

_Noreturn void die2(const char *msg1, const char *msg2) {
    warn2(msg1, msg2);
    dien();
}

void init_dev() {
    if (mount("dev", "/dev", "devtmpfs", MS_NOSUID | MS_NOEXEC, NULL) < 0) {
        warn2("mount", "/dev");
        // /dev will be already mounted if devtmpfs.mount = 1 on the kernel
        // command line or CONFIG_DEVTMPFS_MOUNT is set. Do not consider this
        // an error.
        if (errno != EBUSY) {
            dien();
        }
    }
}

void init_fs(const struct InitOp *ops, size_t count) {
    for (size_t i = 0; i < count; i++) {
        switch (ops[i].op) {
        case OpMount: {
            const struct Mount *m = &ops[i].mount;
            if (mount(m->source, m->target, m->type, m->flags, m->data) < 0) {
                die2("mount", m->target);
            }
            break;
        }
        case OpMkdir: {
            const struct Mkdir *m = &ops[i].mkdir;
            if (mkdir(m->path, m->mode) < 0) {
                warn2("mkdir", m->path);
                if (errno != EEXIST) {
                    dien();
                }
            }
            break;
        }
        case OpMknod: {
            const struct Mknod *n = &ops[i].mknod;
            if (mknod(n->path, n->mode, makedev(n->major, n->minor)) < 0) {
                warn2("mknod", n->path);
                if (errno != EEXIST) {
                    dien();
                }
            }
            break;
        }
        case OpSymlink: {
            const struct Symlink *sl = &ops[i].symlink;
            if (symlink(sl->target, sl->linkpath) < 0) {
                warn2("symlink", sl->linkpath);
                if (errno != EEXIST) {
                    dien();
                }
            }
            break;
        }
        }
    }
}

void init_cgroups() {
    const char *fpath = "/proc/cgroups";
    FILE *f = fopen(fpath, "r");
    if (f == NULL) {
        die2("fopen", fpath);
    }
    // Skip the first line.
    for (;;) {
        int c = fgetc(f);
        if (c == EOF || c == '\n') {
            break;
        }
    }
    for (;;) {
        static const char base_path[] = "/sys/fs/cgroup/";
        char path[sizeof(base_path) - 1 + 65];
        char* name = path + sizeof(base_path) - 1;
        int hier, groups, enabled;
        int r = fscanf(f, "%64s %d %d %d\n", name, &hier, &groups, &enabled);
        if (r == EOF) {
            break;
        }
        if (r != 4) {
            errno = errno ? : EINVAL;
            die2("fscanf", fpath);
        }
        if (enabled) {
            memcpy(path, base_path, sizeof(base_path) - 1);
            if (mkdir(path, 0755) < 0) {
                die2("mkdir", path);
            }
            if (mount(name, path, "cgroup", MS_NODEV | MS_NOSUID | MS_NOEXEC, name) < 0) {
                die2("mount", path);
            }
        }
    }
    fclose(f);
}

void init_console() {
    // init process needs to set up a tty for the container and this is likely
    // not the correct way to do this, although it works when compiling with
    // musl-gcc.
    const char *console_path = "/dev/console";
    die_on(freopen(console_path, "r", stdin) == NULL,
           "freopen failed for stdin");
    die_on(freopen(console_path, "w", stdout) == NULL,
           "freopen failed for stdout");
    die_on(freopen(console_path, "w", stderr) == NULL,
           "freopen failed for stderr");
}

pid_t launch(char **argv, char **envp) {
    int pid = fork();
    if (pid != 0) {
        die_on(pid < 0, "fork");

        return pid;
    }

    if (argv == NULL)
        argv = (char **) default_argv;

    if (envp == NULL)
        envp = (char **) default_envp;

    // Unblock signals before execing.
    sigset_t set;
    sigfillset(&set);
    sigprocmask(SIG_UNBLOCK, &set, 0);

    // Create a session and process group.
    setsid();
    setpgid(0, 0);

    // Terminate the arguments and exec.
    die_on(putenv(DEFAULT_PATH_ENV), "putenv"); // Specify the PATH used for execvpe
    execvpe(argv[0], argv, envp);
    die2("execvpe", argv[0]);
}

int reap_until(pid_t until_pid) {
    for (;;) {
        int status;
        pid_t pid = wait(&status);
        die_on(pid < 0, "wait");

        if (pid == until_pid) {
            // The initial child process died. Pass through the exit status.
            if (WIFEXITED(status)) {
                if (WEXITSTATUS(status) != 0) {
                    fputs("child exited with error\n", stderr);
                }
                return WEXITSTATUS(status);
            }
            fputs("child exited by signal\n", stderr);
            return 128 + WTERMSIG(status);
        }
    }
}

char **read_config(FILE *env_file) {
    if (env_file == NULL) {
        warn("Could not open /env file");
        return NULL;
    }

    char **env = NULL;

    const size_t env_increment = 10;
    size_t env_size = 0;

    for (size_t i = 0; !feof(env_file); i++) {
        char *line = NULL;
        size_t len = 0;
        ssize_t read = getline(&line, &len, env_file);
        if (read == -1)
            break;

        if (line[read - 1] == '\n')
            line[read - 1] = 0;

        if (i + 1 >= env_size) {
            env_size += env_increment;
            env = realloc(env, env_size * sizeof(char *));
            die_on(env == NULL, "not enough mem for env variables");
        }

        env[i] = line;
        env[i + 1] = NULL;
    }
    return env;
}

int main() {
    // Block all signals in init. SIGCHLD will still cause wait() to return.
    sigset_t set;
    sigfillset(&set);
    sigprocmask(SIG_BLOCK, &set, 0);

    // Set up the minimal dependencies to start a container
    // Init /dev and start /dev/console for early debugging
    init_dev();
    init_console();

    FILE *env_file = fopen("/env", "r");
    FILE *cmd_file = fopen("/cmd", "r");

    // env should be an array of "VAR1=string1", "VAR2=string2", ...
    // The array should end with NULL
    char **env = read_config(env_file);
    // cmd should be an array of "command", "param1", "param2", ...
    // The array should end with NULL
    char **cmd = read_config(cmd_file);

    fclose(env_file);
    fclose(cmd_file);

    unlink("/env");
    unlink("/cmd");

    // Turn /rootfs into a mount point so it can be used with mount --move
    die_on(mount("/rootfs", "/rootfs", NULL, MS_BIND, NULL) != 0,
        "mount --bind /rootfs /rootfs");
    die_on(chdir("/rootfs") != 0, "chdir /rootfs");
    // Change the root directory of the mount namespace to the root directory
    // by overmounting / with /rootfs
    die_on(mount(".", "/", NULL, MS_MOVE, NULL) != 0,
        "mount --move . /");
    die_on(chroot(".") != 0, "chroot .");
    die_on(chdir("/") != 0, "chdir /");

    // At this point, we need to make sure the container /dev is initialized
    // as well.
    init_dev();
    init_fs(ops, sizeof(ops) / sizeof(ops[0]));
    init_cgroups();

    pid_t pid = launch(cmd, env);

    //// Reap until the initial child process dies.
    reap_until(pid);
    reboot(RB_AUTOBOOT);
}
