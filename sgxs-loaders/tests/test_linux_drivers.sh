#!/bin/bash -e
#
# Prior to running this script, make sure the system has the following
# configuration:
#
# * Linux: 4.15 generic kernel (e.g. not the Azure kernel)
# * Test dependencies: build-essential dkms docker.io
# * EDP dependencies: pkg-config libssl-dev protobuf-compiler
# * Rust: latest nightly installed with x86_64-fortanix-unknown-sgx target
# * No other SGX drivers or software installed (from any vendor)
#
# Note: you can't run this script multiple times because the FLC drivers make
# CPU configuration changes that the non-FLC drivers don't support.

read -r -d '' DRIVERS <<'EOT' || true
ignore Doesn't compile on Linux 4.15 fc02c5f187e91c36cebe8146a518a314ea817b3109ec4ada78382685fa84d827  linux-1.5/sgx-linux-x64-driver-1.5.80.32783.tar
ignore Doesn't compile on Linux 4.15 5d823bf09ba4243c9cf42e14c9c2ac513ec2bef32d139c6166c41bb68d487eab  linux-1.6/sgx_linux_x64_driver_1.6.100.32783.bin
ignore Doesn't compile on Linux 4.15 a24af7f85f78e00c892f6ec9671f519c543736eb8a412c9044616d7960d82b5c  linux-1.7/sgx_linux_x64_driver_51b2884.bin
ignore Doesn't compile on Linux 4.15 327b8ac815403f54c99f68491e8e4ddcf989bc8446aeff2237f51309fcfc4470  linux-1.8/sgx_linux_x64_driver_4b57088.bin
a337db506f58f058f62a5c70025f8a412501720d261907c3d5c213dfdd9e56cb  linux-1.9/sgx_linux_x64_driver_3abcf82.bin
d0577b406c6cc9ed003b13098777a79bcf2e26de78b26849648e8819a85d3488  linux-2.0/sgx_linux_x64_driver_eb61a95.bin
ignore Doesn't compile on Linux 4.15 6852a49cb67858999b49b0b1d2a1be8c40dd64a4cd7c79449ea9b0b38a833f7f  linux-2.1/ubuntu64-server/sgx_linux_x64_driver_1bf506e.bin
ignore Doesn't compile on Linux 4.15 228c244a096b51c84953143fb400f39ea01e98ab020cd4487bcd92b80fdcc996  linux-2.1.1/ubuntu64-server/sgx_linux_x64_driver_1bf506e.bin
ignore Doesn't compile on Linux 4.15 8c3d771bf6cc33bc86df082315ccb5376dbc2c3896804ca4684f913b10d0dd15  linux-2.1.2/ubuntu64-server/sgx_linux_x64_driver_1bf506e.bin
ignore Doesn't compile on Linux 4.15 4111fa2a04c5e632486ab74098efc32da354a75d95474dadd7ea020f77611b09  linux-2.1.3/ubuntu64-server/sgx_linux_x64_driver_1bf506e.bin
1ce9f4d9deaa26ac912dde451956c02ca99a5bab234d80282546d404af51b70c  linux-2.2/ubuntu64-server/sgx_linux_x64_driver_dc5858a.bin
68db2bf49d911f23b3219c8e731b90c197aebd1094d8f8846b95fbaca4ab2a9e  linux-2.3/ubuntu16.04-server/sgx_linux_x64_driver_4d69b9c.bin
563221244d525cc7a76632c600e243303d5c11a2b2009fd25ef99a6a3e5ffb79  linux-2.3.1/ubuntu16.04/sgx_linux_x64_driver_4d69b9c.bin
e78e8688a90c8dbaee899df2ae50a1b4657baa89b4ec3a55092fb32515993f1c  linux-2.4/ubuntu16.04-server/sgx_linux_x64_driver_778dd1f.bin
d304cf2c129a250840faaa6bc4b40b7f85389828c386ca1ddcd87356099f80c6  linux-2.5/ubuntu16.04-server/sgx_linux_x64_driver_2.5.0_2605efa.bin
95cda491a8d77f972cd653f84f092c70a534ea69e2794b1b42c439376688e89b  linux-2.5/ubuntu16.04-server/sgx_linux_x64_driver_f7dc97c.bin
0c3508dcc85a7987c559798d296c558bf1e2050f74043deeaa1c7bf2ed3a9e47  linux-2.6/ubuntu16.04-server/sgx_linux_x64_driver_2.5.0_2605efa.bin
b2e19c7df87b89e00e97dc517d769920694dda28b9a9f1d9a2d7ec78d1fc424b  sgx-linux/2.7/distro/ubuntu16.04-server/sgx_linux_x64_driver_2.6.0_4f5bb63.bin
bb068abd5b122156df00fd6ed4c23802e1c70706d2b829db212557a6a97384c5  sgx-linux/2.7.1/distro/ubuntu16.04-server/sgx_linux_x64_driver_2.6.0_4f5bb63.bin
5455a1f772b2f8eee4a73dd2d17a81f970508be0cf6b9d19ca2678745d590d9a  sgx-linux/2.8/distro/ubuntu16.04-server/sgx_linux_x64_driver_2.6.0_51c4821.bin
d14b98045222fa0381b6bba939786012acbb9bc15886284821a8fc4a3598d3ca  sgx-linux/2.9/distro/ubuntu16.04-server/sgx_linux_x64_driver_2.6.0_95eaa6f.bin
3c0e05ee4b5fb0ad120f6c3220e0e127d2051038549a5cb024b5916249e7adbf  sgx-linux/2.9.1/distro/ubuntu16.04-server/sgx_linux_x64_driver_2.6.0_95eaa6f.bin
8c54059f87dc8254130b983651609bb7e70658cd366d944d2a818385632b8066  sgx-linux/2.10/distro/ubuntu16.04-server/sgx_linux_x64_driver_2.6.0_602374c.bin
da52d9970c46834e02bcb3b21c2430e798c9499c5fc0238314fdb2024418007d  sgx-linux/2.11/distro/ubuntu16.04-server/sgx_linux_x64_driver_2.6.0_b0a445b.bin
ignore Doesn't unload properly 3308d39e3de814a38cada256cb467505f487282ba1a51c7b9f0413d2decb0603  dcap-1.0/sgx_linux_x64_driver_dcap_36594a7.bin
ignore Doesn't unload properly 52867630590da8352cad6012018cf5eadd2a90dc8b38c832cd72e0d83be6ff9a  dcap-1.0.1/dcap_installer/ubuntuServer1604/sgx_linux_x64_driver_dcap_4f32b98.bin
ignore Doesn't unload properly 329d510eb0efb91e2a8bc0e25df2940516a2fedd9a3b08bd7da417cf236097b4  dcap-1.1/linux/dcap_installers/ubuntuServer16.04/sgx_linux_x64_driver_dcap_1.1.100.2786ad8.bin
ignore Doesn't unload properly 3399d6e145f6f7115babc43c4ec058be65e535522862529acfac5041add8a264  dcap-1.2/linux/dcap_installers/ubuntuServer16.04/sgx_linux_x64_driver_1.12_c110012.bin
ignore Doesn't unload properly d950af2bf47ab7b9e2f979e4d92484aad2455f3410138cbfec9efdc041573f20  sgx-dcap/1.3/linux/distro/ubuntuServer16.04/sgx_linux_x64_driver_1.13.bin
9d0fe7f4a8c8b0a606dc6062d214d4332c34c4bfc406c626b721a9fa40b1d232  sgx-dcap/1.3.1/linux/distro/ubuntuServer16.04/sgx_linux_x64_driver_1.20.bin
2769d3250c516e8e4e144ad672af0e9598d31afc2dada792229e69b72d595465  sgx-dcap/1.4/linux/distro/ubuntuServer16.04/sgx_linux_x64_driver_1.21.bin
b1bc6ae32790642934535c4011ad29c3a6eea79b96cfaef47317b00727892983  sgx-dcap/1.5/linux/distro/ubuntuServer16.04/sgx_linux_x64_driver_1.21.bin
ignore Doesn't load properly 07df5b2e18873cad4d478f71313f8a5e597ab43717eb1ea3c2944fcf9b044963  sgx-dcap/1.6/linux/distro/ubuntuServer16.04/sgx_linux_x64_driver_1.32.bin
c7fc34486b330651f081eb97aec4412486dfb514056f71951df9ed420e52b5db  sgx-dcap/1.6/linux/distro/ubuntuServer16.04/sgx_linux_x64_driver_1.33.bin
64c63f1e5db08271fcd123dcee1de239bade87496d7150231bc10a07b84bf30b  sgx-dcap/1.7/linux/distro/ubuntu16.04-server/sgx_linux_x64_driver_1.35.bin
8d52007399aaf7da64a2dd8f76be6de0deee15add04341538c846703adbe0a63  sgx-dcap/1.8/linux/distro/ubuntu16.04-server/sgx_linux_x64_driver_1.36.bin
EOT

cd "$( dirname "${BASH_SOURCE[0]}" )"

cargo test --test loaders --no-run

sudo docker rm -f aesmd || true
sudo docker pull fortanix/aesmd

echo "$DRIVERS"|while read hash path; do
    if [ $hash = ignore ]; then
        continue
    fi

    case "$path" in
        sgx-*)
            second_path_component="${path#*/}"
            version="${path%%/*}/${second_path_component%%/*}"
            ;;
        *)
            version="${path%%/*}"
            ;;
    esac
    echo "===> TESTING driver $version"

    echo "= Downloading driver $version"
    file="sgx-drivers/$path"
    mkdir -p "$(dirname "$file")"
    wget -nv --continue -O "$file" "https://download.01.org/intel-sgx/$path"
    echo $hash "$file" | sha256sum -c

    echo "= Installing driver $version"
    sudo bash "$file"
    # not all drivers load automatically
    sudo modprobe isgx || true

    echo "= Starting AESM with version $version"
    sudo docker run --detach --privileged --restart no --volume /dev:/dev/host --volume /var/run/aesmd:/var/run/aesmd --name aesmd fortanix/aesmd
    while ! sudo docker logs aesmd|&grep -q 'The server sock is'; do sleep 0.1; done

    echo "= Running test for version $version"
    cargo test --test loaders -- sgxdevice

    echo "= Stopping AESM"
    sudo docker rm -f aesmd

    echo "= Uninstalling driver $version"
    sudo /opt/intel/sgxdriver/uninstall.sh
done
