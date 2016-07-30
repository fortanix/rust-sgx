# Upgrade guide

Most version upgrades should be seamless, but if any changes are required as
the result of an upgrade, they will be described here.

In general, you must use libenclave-tools of the same version as the libenclave
used in your crate. Regarding the enclave<->user interface, libenclave and
enclave-interface of the same major version (minor version for 0.x versions)
should be compatible. See also the [libenclave ABI compatibility
chart](LIBENCLAVE-ABI.md#abi-version-compatibility).

  * [Upgrading from enclave-interface 0.1.0 to 0.1.1](#upgrading-from-enclave-interface-010-to-011)
  * [Upgrading from libenclave 0.1.2 to 0.1.3](#upgrading-from-libenclave-012-to-013)
  * [Upgrading from libenclave 0.1.0 to 0.1.2](#upgrading-from-libenclave-010-to-012)

## Upgrading from enclave-interface 0.1.0 to 0.1.1

The signatures of `sgxs::loader::Map::tcss` and `enclave_interface::tcs::enter`
have changed. The returned mapping must now be mutable and you must pass a
mutable reference to enter.

## Upgrading from libenclave 0.1.2 to 0.1.3

No changes required.

## Upgrading from libenclave 0.1.0 to 0.1.2

### New driver

Intel published their [draft SGX
driver](http://lkml.iu.edu/hypermail/linux/kernel/1604.3/00954.html). It's
recommended to use that instead of the `sgxdev` driver. The patches have been
assembled for an external build in [this repository](../isgx). Build using:

```
make -C /lib/modules/$(uname -r)/build M=$(pwd) modules
```

In your code, replace every use of `sgxs::sgxdev` with `sgxs::isgx`. No other
changes should be needed.

### Rearrange source files

The build process was streamlined. The enclave and user artifacts are now in
separate crates instead of combined in a single one. You'll need to split up
your crate as follows:

  1. Go to your enclave root directory
  2. Create trusted/ and untrusted/
  3. Move src/trusted/ to trusted/src/
  4. Move src/untrusted/ to untrusted/src/
  5. Copy Cargo.toml to trusted/
  6. Move Cargo.toml to untrusted/
  7. Edit trusted/Cargo.toml
    - Set `license` to `AGPL-3.0+`
    - Set `crate-type` to `dylib` under `[lib]` section
    - Remove `path` under `[lib]` section
    - Remove `[[bin]]` section
    - Remove dependency on `sgxs` and `enclave-interface`
    - Update dependency on `enclave` to `=0.1.2`
  8. Edit untrusted/Cargo.toml
    - Set `name` to `enclave-example-runner`, or your preference
    - Set `license` to `GPL-2.0+`, or your compatible preference
    - Remove `[lib]` section
    - Remove `path` under `[[bin]]` section
    - Set `crate-type` to `dylib` under `[lib]` section
    - Remove dependency on `enclave`
    - Update dependency on `enclave-interface` to `0.1.0` (no equals sign)
    - Remove feature for `enclave/debug`

You can now run `cargo build-enclave` in trusted/ and a regular `cargo build`
in untrusted/.
