#!/bin/bash -ex

ARCH=x86_64
TARGET=$ARCH-linux-musl
OUTPUT=/usr/local

# Ancient binutils versions don't understand debug symbols produced by more recent tools.
# Apparently applying `-fPIC` everywhere allows them to link successfully.
export CFLAGS="-fPIC $CFLAGS"

git clone https://github.com/richfelker/musl-cross-make
cd musl-cross-make
# The latest branch 0.9.9 doesn't have the musl 1.2.2 library. Checking out a commit that does
# patch https://www.openwall.com/lists/musl/2020/11/19/1
git checkout 0f22991b8d47837ef8dd60a0c43cf40fcf76217a

make -j$(nproc) TARGET=$TARGET MUSL_VER=1.2.2
make install TARGET=$TARGET MUSL_VER=1.2.2 OUTPUT=$OUTPUT

cd -

# Install musl library to make binaries executable
ln -s $OUTPUT/$TARGET/lib/libc.so /lib/ld-musl-$ARCH.so.1
echo $OUTPUT/$TARGET/lib >> /etc/ld-musl-$ARCH.path
