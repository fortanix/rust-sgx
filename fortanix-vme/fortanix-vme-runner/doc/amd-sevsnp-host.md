# Host Configuration for running Amd SEV/SNP VM
=============================================

This document outlines the steps to prepare your host system for running QEMU. This setup ensures that your host kernel supports VSOCK, permissions are handled correctly, and the configuration survives reboots.


## VSOCK Support

### 1. Load Kernel Modules

For vhost-vsock to work, the host needs the vhost_vsock kernel module.

#### Manual Loading (Immediate)

```sh
sudo modprobe vhost_vsock
```

#### Automated Loading (Persistent)

To ensure the module loads automatically every time the system boots, use modules-load.d.

Create a configuration file:

```sh
echo "vhost_vsock" | sudo tee /etc/modules-load.d/vhost-vsock.conf
```

Verify it is loaded after a reboot with `lsmod | grep vhost_vsock`.

### 2. Configure Permissions (Udev)

By default, `/dev/vhost-vsock` is usually owned by `root:root` with strict permissions. To allow QEMU (running as a non-root user) to access it, you should assign it to a group like `kvm`.

Create the Udev Rule: Create a new rule file in /etc/udev/rules.d/:

```sh
echo 'KERNEL=="vhost-vsock", GROUP="kvm", MODE="0660"' | sudo tee /etc/udev/rules.d/99-vhost-vsock.rules
```

Rule values of the entry;

* `KERNEL=="vhost-vsock"`: Matches the specific device.

* `GROUP="kvm"`: Assigns the device to the kvm group.

* `MODE="0660"`: Grants read/write access to the owner (root) and the group (kvm).

#### Apply the Rule (Immediate):

```sh
sudo udevadm control --reload-rules
sudo udevadm trigger
```

#### Check Permissions:

```sh
ls -l /dev/vhost-vsock
```

Expected output: `crw-rw---- 1 root kvm ... /dev/vhost-vsock`

### 3. User Group Membership

Ensure your user account is a member of the kvm group.

```sh
sudo usermod -aG kvm $USER
```

Note: You must log out and log back in (or restart your session) for this change to take effect.
