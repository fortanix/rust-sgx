<!-- TODO (RTE-739, RTE-728): clean up setup -->
# Blobs

These blobs have been vendored from the following locations

## init 
Tweaked the code to build the `init` executable from [here](https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/blob/f718dea60a9d9bb8b8682fd852ad793912f3c5db) and placed it under `build_init/`.
`build.rs` uses the shell script `build_init/update_init.sh` to place the generated `init` artifact in this folder and keep it up-to-date.

Changes made are as follows:
1. Remove function `init_nsm_driver`: initialization of Nitro Secure Module driver
2. Remove function `enclave_ready`: sending signal to nitro-cli that the enclave has started
3. Remove global vars for above two functions.

To see the diff:
```sh
diff -c10 <(curl https://raw.githubusercontent.com/aws/aws-nitro-enclaves-sdk-bootstrap/f718dea60a9d9bb8b8682fd852ad793912f3c5db/init/init.c) blobs/build_init/init.c
```

## bzImage
Upstream kernel, configured for the guest VM.

## config.bzImage
The kernel configuration used to build `bzImage`.

## OVMF
Defaults copied from noble installation, taken from `/usr/share/ovmf/OVMF.fd` and `/usr/share/ovmf/OVMF.amdsev.fd` respectively

## EFI boot stub
Defaults copied from noble package `sytemd-boot-efi` version `255.4-1ubuntu8.12`, installed under path `/usr/lib/systemd/boot/efi/linuxx64.efi.stub` by default
