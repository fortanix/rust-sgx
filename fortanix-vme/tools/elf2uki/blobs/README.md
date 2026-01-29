<!-- TODO (RTE-739): clean up setup -->
# Blobs

These blobs have been vendored from the following locations

## init 
Tweaked the code to build the `init` executable from [here](https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/blob/f718dea60a9d9bb8b8682fd852ad793912f3c5db) and placed it under `build_init/`.
Use the shell script `build_init/update_init.sh` to place the generated `init` artefact in this folder.

## vmlinuz-{version}
Ubuntu kernel, extracted from package linux-image-{version}
