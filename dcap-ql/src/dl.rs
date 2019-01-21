use std::io::Result as IoResult;

use libc::{RTLD_GLOBAL, RTLD_NOW};

use dcap_ql_sys::*;
use sgx_isa::{Report, Targetinfo};
use sgxs_loaders::sgx_enclave_common::dl;
use sgxs_loaders::sgx_enclave_common::dl::os::unix::Library as Dl;

struct DcapQl {
    _library: dl::Library,
    get_target_info: GetTargetInfoFn,
    get_quote_size: GetQuoteSizeFn,
    get_quote: GetQuoteFn,
}

lazy_static! {
    static ref DCAP_QL: IoResult<DcapQl> = unsafe {
        // Open globally so that `::enclave_loader` can find what it needs
        let library = Dl::open(Some(LIBRARY), RTLD_NOW | RTLD_GLOBAL)?;
        let get_target_info = *library.get::<GetTargetInfoFn>(SYM_GET_TARGET_INFO)?;
        let get_quote_size = *library.get::<GetQuoteSizeFn>(SYM_GET_QUOTE_SIZE)?;
        let get_quote = *library.get::<GetQuoteFn>(SYM_GET_QUOTE)?;
        Ok(DcapQl { _library: library.into(), get_target_info, get_quote_size, get_quote })
    };
}

pub unsafe fn get_target_info(target_info: &mut Targetinfo) -> u32 {
    match *DCAP_QL {
        Ok(ref ql) => (ql.get_target_info)(target_info),
        Err(_) => Quote3Error::InterfaceUnavailable as _,
    }
}

pub unsafe fn get_quote_size(quote_size: &mut u32) -> u32 {
    match *DCAP_QL {
        Ok(ref ql) => (ql.get_quote_size)(quote_size),
        Err(_) => Quote3Error::InterfaceUnavailable as _,
    }
}

pub unsafe fn get_quote(report: &Report, quote_size: u32, quote: *mut u8) -> u32 {
    match *DCAP_QL {
        Ok(ref ql) => (ql.get_quote)(report, quote_size, quote),
        Err(_) => Quote3Error::InterfaceUnavailable as _,
    }
}

pub fn load() -> Result<(), &'static str> {
    if DCAP_QL.is_err() {
        Err("Failed to load sgx_dcap_ql")
    } else {
        Ok(())
    }
}
