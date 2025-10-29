extern crate dcap_ql_sys;
#[cfg(not(feature = "link"))]
extern crate libc;

extern crate sgxs_loaders;

use anyhow::Error;
use anyhow::anyhow;
use num_traits::FromPrimitive;

pub use self::dcap_ql_sys::Quote3Error;
use sgx_isa::{Report, Targetinfo};
use self::sgxs_loaders::sgx_enclave_common::dl::os::unix::Library as Dl;
use self::sgxs_loaders::sgx_enclave_common::Library as EnclaveCommonLibrary;

#[cfg(feature = "link")]
use self::dcap_ql_sys::{get_quote, get_quote_size, get_target_info};
#[cfg(not(feature = "link"))]
use self::dl::{get_quote, get_quote_size, get_target_info};

#[cfg(not(feature = "link"))]
mod dl;

fn err_code_to_result(err: u32) -> Result<(), Quote3Error> {
    match Quote3Error::from_u32(err) {
        Some(Quote3Error::Success) => Ok(()),
        Some(e) => Err(e),
        _ => Err(Quote3Error::InvalidParameter),
    }
}

/// Obtain the `Targetinfo` for the Quoting Enclave.
///
/// Use this `Targetinfo` when calling `EREPORT` in your enclave to generate
/// the report that will be passed into `quote()`.
pub fn target_info() -> Result<Targetinfo, Quote3Error> {
    unsafe {
        let mut targetinfo = Targetinfo::default();
        err_code_to_result(get_target_info(&mut targetinfo))?;
        Ok(targetinfo)
    }
}

/// Turn a `Report` into a quote.
///
/// Call the quoting enclave to get a quote. The quoting enclave will sign the
/// `Report` if the `Report` is valid and generated with the right `Targetinfo`.
pub fn quote(report: &Report) -> Result<Vec<u8>, Quote3Error> {
    unsafe {
        let mut quote_size = 0;
        err_code_to_result(get_quote_size(&mut quote_size))?;

        let mut quote = vec![0; quote_size as _];
        err_code_to_result(get_quote(&report, quote_size, quote.as_mut_ptr()))?;
        Ok(quote)
    }
}

/// Returns `true` if the DCAP Quoting Library could be loaded.
///
/// This doesn't indicate anything else. For example, loading the quoting
/// enclave might still fail even if this returns `true`.
pub fn is_loaded() -> bool {
    #[cfg(not(feature = "link"))]
    {
        dl::load().is_ok()
    }
    #[cfg(feature = "link")]
    {
        true
    }
}

/// Get the enclave loader that is available due to linking with the DCAP
/// Quoting Library.
///
/// Since DCAP is being used, assume that no EINITTOKEN provider is necessary.
pub fn enclave_loader() -> Result<EnclaveCommonLibrary, Error> {
    #[cfg(not(feature = "link"))]
    dl::load().map_err(|e| anyhow!(e))?;
    // NB. libsgx_dcap_ql.so.1 transitively links to libsgx_enclave_common.so.1
    // so we should be able to find it already loaded.
    // We can't use the library from `mod dl` if `not(feature = "link")`,
    // because that is not the right library.
    let lib = EnclaveCommonLibrary::load(Some(Dl::this().into()))
        .or(EnclaveCommonLibrary::load(None))?;
    Ok(lib.build())
}
