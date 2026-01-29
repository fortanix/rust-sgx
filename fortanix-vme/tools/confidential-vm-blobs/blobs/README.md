<!-- TODO (RTE-739, RTE-728): clean up setup -->
# Blobs

These blobs have been vendored from the following locations

## init 
Tweaked the code to build the `init` executable from [here](https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/blob/f718dea60a9d9bb8b8682fd852ad793912f3c5db) and placed it under `build_init/`.
`build.rs` uses the shell script `build_init/update_init.sh` to place the generated `init` artefact in this folder and keep it up-to-date.

## vmlinuz-{version}
Ubuntu kernel, extracted from noble package `linux-image-{version}`.

## OVMF
Defaults copied from noble installation, taken from `/usr/share/ovmf/OVMF.fd` and `/usr/share/ovmf/OVMF.amdsev.fd` respectively

## EFI boot stub
Defaults copied from noble package `sytemd-boot-efi` version `255.4-1ubuntu8.12`, installed under path `/usr/lib/systemd/boot/efi/linuxx64.efi.stub` by default
