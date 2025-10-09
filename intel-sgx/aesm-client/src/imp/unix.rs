use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::Duration;

use unix_socket::UnixStream;
#[cfg(feature = "sgxs")]
use sgxs::sigstruct::{Attributes, Sigstruct};

pub use error::Result;

mod aesm_protobuf;

#[cfg(feature = "sgxs")]
use GetLaunchTokenRequest;

#[derive(Clone, Debug, Default)]
pub struct AesmClient {
    path: Option<PathBuf>,
}

impl AesmClient {
    pub fn new() -> Self {
        Default::default()
    }

    fn open_socket(&self) -> Result<UnixStream> {
        lazy_static! {
            static ref AESM_SOCKET_ABSTRACT_PATH: PathBuf = {
                // This is defined in <linux/un.h>, although if aesm didn't pad
                // its address we wouldn't need to use it here.
                const UNIX_PATH_MAX: usize = 108;

                // The address of the AESM socket is "sgx_aesm_socket_base" followed by
                // enough NULs to pad to UNIX_PATH_MAX (and with a leading NUL to indicate
                // the abstract namespace).
                let mut path = [0; UNIX_PATH_MAX];
                path[1..21].copy_from_slice(b"sgx_aesm_socket_base");
                OsStr::from_bytes(&path).into()
            };
        };
        static AESM_SOCKET_FILE_PATH: &'static str = "/var/run/aesmd/aesm.socket";

        // AESM only accepts one request per connection, so we have to open
        // a fresh socket here.
        let path = if let Some(ref path) = self.path {
            &**path
        } else if Path::new(AESM_SOCKET_FILE_PATH).exists() {
            Path::new(AESM_SOCKET_FILE_PATH)
        } else {
            &**AESM_SOCKET_ABSTRACT_PATH
        };

        let sock = UnixStream::connect_timeout(path, Duration::from_micros(aesm_protobuf::LOCAL_AESM_TIMEOUT_US as _))?;
        let _ = sock.set_write_timeout(Some(Duration::from_micros(aesm_protobuf::LOCAL_AESM_TIMEOUT_US as _)))?;
        Ok(sock)
    }

    /// Obtain launch token
    #[cfg(feature = "sgxs")]
    pub fn get_launch_token(
        &self,
        sigstruct: &Sigstruct,
        attributes: Attributes,
    ) -> Result<Vec<u8>> {
        let mut req = GetLaunchTokenRequest::new();
        req.set_mr_enclave(sigstruct.enclavehash.to_vec());
        // The field in the request protobuf is called mr_signer, but it wants the modulus.
        req.set_mr_signer(sigstruct.modulus.to_vec());
        req.set_se_attributes(attributes.as_ref().to_vec());
        req.set_timeout(aesm_protobuf::REMOTE_AESM_TIMEOUT_US);

        let mut res = self.transact(req)?;

        let token = res.take_token();

        Ok(token)
    }
}

impl crate::unix::AesmClientExt for crate::AesmClient {
    fn with_path<P: AsRef<Path>>(path: P) -> Self {
        crate::AesmClient {
            inner: self::AesmClient {
                path: Some(path.as_ref().to_owned()),
            },
        }
    }
}
