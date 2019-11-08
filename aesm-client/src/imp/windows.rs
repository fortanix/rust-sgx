use std::sync::Arc;
use std::fmt;

use winapi::_core::ffi::c_void;

use sgxs::sigstruct::{Attributes, Sigstruct};


use error::{Error, Result};
use {QuoteInfo, QuoteResult, QuoteType};

extern crate libloading as dl;

#[derive(Clone, Debug, Default)]
pub struct AesmClient {
    _private: (),
    library: Library,
}
const LIBRARY: &str = "sgx_uae_service.dll";

const SYM_GET_LAUNCH_TOKEN: &[u8] = b"get_launch_token\0";
type GetLaunchTokenFn = unsafe extern "system" fn(
    signature: *const c_void,
    attribute: *const c_void,
    launch_token: *mut c_void,
) -> u32;

const SYM_SGX_GET_QUOTE: &[u8] = b"sgx_get_quote\0";
type SgxGetQuoteFn = unsafe extern "system" fn(
    p_report: *const c_void,
    quote_type: u32,
    sgx_spid_t: *const c_void,
    sgx_quote_nonce_t: *const c_void,
    p_sig_rl: *const u8,
    sig_rl_size: u32,
    p_qe_report: *mut c_void,
    p_quote: *mut c_void,
    quote_size: u32
) -> u32;

const SYM_SGX_INIT_QUOTE: &[u8] = b"sgx_init_quote\0";
type SgxInitQuoteFn = unsafe extern "system" fn(
    p_target_info: *mut c_void,
    p_gid: *mut c_void,
) -> u32;

struct InnerLibrary {
    library: dl::Library,
    pub init_quote: SgxInitQuoteFn,
    pub get_quote: SgxGetQuoteFn,
    pub get_launch_token: GetLaunchTokenFn,
}
impl fmt::Debug for InnerLibrary {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("InnerLibrary")
            .field("library", &self.library)
            .field("init_quote", &(self.init_quote as *const c_void))
            .field(
                "get_quote",
                &(self.get_quote as *const c_void),
            )
            .field(
                "get_launch_token",
                &(self.get_launch_token as *const c_void),
            )
            .finish()
    }
}

#[derive(Clone, Debug)]
struct Library {
    inner: Arc<InnerLibrary>,
}
impl std::default::Default for Library {
    fn default() -> Self {
        unsafe {
            let library = dl::Library::new(LIBRARY)
                .expect("Couldn't find sgx_uae_service.dll");
            let init_quote = *library.get::<SgxInitQuoteFn>(SYM_SGX_INIT_QUOTE)
                .expect("failed to get dll api function sgx_init_quote");
            let get_quote = *library.get::<SgxGetQuoteFn>(SYM_SGX_GET_QUOTE)
                .expect("failed to get dll api function sgx_get_quote");
            let get_launch_token = *library.get::<GetLaunchTokenFn>(SYM_GET_LAUNCH_TOKEN)
                .expect("failed to get dll api function get_launch_token");

            Library { inner : Arc::new(InnerLibrary {
                library,
                init_quote,
                get_quote,
                get_launch_token,
            })}
        }
    }
}
impl Library {
    pub fn get_inner_library(&self) -> Arc<InnerLibrary> {
        self.inner.clone()
    }
}

impl AesmClient {
    pub fn new() -> Self {
        AesmClient::default()
    }

    pub fn try_connect(&self) -> Result<()> {
        // !!! try using QueryServiceStatusEx
        libloading::Library::new("sgx_uae_service.dll")?;
        Ok(())
    }

    fn get_library(&self) -> Arc<InnerLibrary> {
        self.library.get_inner_library()
    }

    pub fn init_quote(&self) -> Result<QuoteInfo> {
        let mut target_info: Vec<u8> = vec![0; sgx_isa::Targetinfo::UNPADDED_SIZE];
        let mut gid: Vec<u8> = vec![0; 4];
        unsafe {
            let lib = self.get_library();
            let error  = (lib.init_quote)(
                target_info.as_mut_ptr() as _,
                gid.as_mut_ptr() as _,
            );
            if error != 0 {
                return Err(Error::AesmCode(error.into()));
            }
        }
        let quote_info: QuoteInfo = QuoteInfo { target_info, gid };

        return Ok(quote_info);
    }

    pub fn get_quote(
        &self,
        session: &QuoteInfo,
        report: Vec<u8>,
        spid: Vec<u8>,
        sig_rl: Vec<u8>,
    ) -> Result<QuoteResult> {
        use sgx_isa::Report;
        let nonce = [0u8; 64];
        let quote_buffer_size = session.quote_buffer_size(&sig_rl);
        let mut qe_report: Vec<u8> = vec![0; Report::UNPADDED_SIZE];
        let mut quote: Vec<u8> = vec![0; quote_buffer_size as usize];

        unsafe {
            let lib = self.get_library();

            let (sig_rl_in, sig_rl_size_in )= match sig_rl.len() {
                0 => (std::ptr::null(), 0),
                s => (sig_rl.as_ptr(), s)
            };

            let error = (lib.get_quote)(
                    report.as_ptr() as _,
                    QuoteType::Linkable.into(),
                    spid.as_ptr() as _,
                    nonce.as_ptr() as _,
                    sig_rl_in,
                    sig_rl_size_in as _,
                    qe_report.as_mut_ptr() as _,
                    quote.as_mut_ptr() as _,
                    quote_buffer_size,
                );
                if error != 0 {
                    return Err(Error::AesmCode(error.into()));
                }
        }
        return Ok(QuoteResult::new(quote, qe_report));
    }

    pub fn get_launch_token(
        &self,
        sigstruct: &Sigstruct,
        attributes: Attributes
    ) -> Result<Vec<u8>> {
        let mut licence_token = vec![0; sgx_isa::Einittoken::UNPADDED_SIZE];
        unsafe {

            let lib = self.get_library();

            let error = (lib.get_launch_token)(
                    sigstruct.as_ref().as_ptr() as _,
                    attributes.as_ref().as_ptr() as _,
                    licence_token.as_mut_ptr() as _,
                );
            if error != 0 {
                return Err(Error::AesmCode(error.into()));
            }
        }
        return Ok(licence_token);
    }
}
