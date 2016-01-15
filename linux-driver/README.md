# linux-driver

This is a very bare-bones SGX EPC driver. It exposes ENCLS pretty much directly
to userspace. There are probably local privilege escalation vulnerabilites. Not
intended for production use.

## Kernel module

### Build requirements

The module build has been tested on Linux 3.13 and 4.2. You'll probably want a
recent kernel for generic hardware support anyway.

You'll need a recent version of GNU `as` that supports the `encls` instruction.
2.25.1 is ok, 2.24 is not.

### Building

```sh
make
```

### Loading

```sh
sudo insmod sgxmod.ko
```

### Device file

You have to manually create the device file to expose the device to userspace.

IMPORTANT: Look in the dmesg for the correct device major number

```sh
sudo mknod -m 666 /dev/sgx c 245 0
```

## User test program

Three test utilities should've been built at the same time as the kernel
module.

### clear <n>

Calls ERMOVE on the fist N pages.

### user

Builds a simple enclave, while recording timing information of the ENCLS
instruction.

### user_multi

The same as `user`, except using a single system call to perform multiple ENCLS
instructions.
