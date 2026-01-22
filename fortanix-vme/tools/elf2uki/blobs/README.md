# Blobs

These blobs have been vendored from the following locations

## init 
Tweaked the code to build the `init` executable from [here](https://github.com/aws/aws-nitro-enclaves-sdk-bootstrap/blob/f718dea60a9d9bb8b8682fd852ad793912f3c5db) and placed it under `build_init/`.
Use the shell script `build_init/update_init.sh` to place the generated `init` artefact in this folder.

## ukify.py
Vendored from [here](https://github.com/systemd/systemd/blob/b61aeeb315c2c9216acb2d960cd944b6ab8ef398/src/ukify/ukify.py)

<!-- TODO: verify this and find a cleaner setup -->
Installation steps

```shell
python3 -m venv .venv
source .venv/bin/activate
pip install pefile
```
