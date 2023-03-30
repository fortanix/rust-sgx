#!/bin/bash -ex

workdir=$(mktemp -d /tmp/tmp_build_eif.XXXXXX)
output=${PWD}/enclave.eif

pushd ${workdir}

# 1. Create initramfs
# 1.1. Create root directory structure
mkdir root
mkdir root/rootfs
mkdir root/rootfs/dev
mkdir root/rootfs/proc
mkdir root/rootfs/run
mkdir root/rootfs/tmp
mkdir root/rootfs/sys
mkdir root/rootfs/bin

# 1.1.1 Downloading required blobs
curl 'https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/main/blobs/x86_64/init' --output root/init
chmod u+x root/init
curl 'https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/main/blobs/x86_64/nsm.ko' --output root/nsm.ko

# 1.1.2 Creating hello world executable
# 1.1.2.1 Build hello world executable
mkdir make_exec
pushd make_exec
echo '#include <stdio.h>
#include <unistd.h>

void main() {
	int cnt = 0;
	while(1) {
		printf("[%3i] Hello world!\n", cnt);
		sleep(1);
		cnt++;
	}
}' > main.c
gcc -o a.out main.c -static -static-libgcc -flto
popd

# 1.1.2.2 Place hello world at right location
cp make_exec/a.out root/rootfs/bin/a.out

# 1.1.3 Creating cmd file (<exec_name> <param1> <param2> ...)
echo "/bin/a.out" > root/cmd

# 1.1.4 Creating cmd file ("VAR1=string1", "VAR2=string2")
echo "" > root/env

# 1.2. Create ramfs
find root -exec touch -h --date=@1 {} +
pushd root
find * .[^.*] -print0 | sort -z | cpio -o -H newc -R +0:+0 --reproducible --null | gzip -n > ../initramfs
popd




# 2. Download kernel
curl 'https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/main/blobs/x86_64/bzImage' --output bzImage
curl 'https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/main/blobs/x86_64/bzImage.config' --output bzImage.config
curl 'https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/main/blobs/x86_64/cmdline' --output cmdline


# 3. Build eif
# 3.1 Download nitro-enclaves-image-format
git clone https://github.com/aws/aws-nitro-enclaves-image-format

# 3.2 Build eif
pushd aws-nitro-enclaves-image-format
cargo run \
	--example eif_build \
	-- \
	--kernel ${workdir}/bzImage \
	--kernel_config ${workdir}/bzImage.config \
	--cmdline "$(cat ${workdir}/cmdline)" \
	--ramdisk ${workdir}/initramfs \
	--output ${output}
popd

echo "eif file written to ${output}"
# To debug one can use:
#   qemu-system-x86_64 -kernel ./bzImage -initrd ./initramfs -nographic -append "console=ttyS0"
# however keep in mind that the AWS init process tries to connect to VSOCK address 3 port 9000
# (see https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/blob/746ec5d2713e539b94e651601b5c24ec1247c955/init/init.c#L370)

#nitro-cli run-enclave --cpu-count 2 --eif-path ${output}  --memory 512 --debug-mode

popd

