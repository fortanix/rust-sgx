# tdx-ql

Rust wrapper crate for Intel TDX guest attestation IOCTLs. It talks to the
Linux TDX guest driver via `/dev/tdx-guest` to request TDREPORT data and
related attestation inputs that are later used to generate a quote.

## References

- Intel Trust Domain Extensions (TDX) documentation:
  <https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html>
- Linux TDX guest driver ABI (`/dev/tdx-guest`) documentation:
  <https://docs.kernel.org/virt/coco/tdx-guest.html>
- Linux TDX guest driver source (`drivers/virt/coco/tdx-guest/`):
  <https://github.com/torvalds/linux/blob/master/drivers/virt/coco/tdx-guest/>
- Linux TDX architecture and attestation background:
  <https://www.kernel.org/doc/html/latest/arch/x86/tdx.html>
