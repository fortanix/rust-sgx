use aesm_client::AesmClient;
#[cfg(target_os = "windows")]
use sgxs_loaders::enclaveapi;
#[cfg(target_os = "linux")]
use sgxs_loaders::isgx;
use sgxs_loaders::sgx_enclave_common;

macro_rules! test_loader {
    ($loader:expr) => {
        let mut loader = $loader
            .expect("enclave loader initialization error")
            .einittoken_provider(AesmClient::new())
            .build();

        report_test::report(&Default::default(), &mut loader).expect("error getting report");
    }
}

#[cfg_attr(not(target_os = "windows"), ignore)]
#[test]
fn enclaveapi() {
    #[cfg(target_os = "windows")]
    test_loader!(enclaveapi::Sgx::new());
}

#[cfg_attr(not(target_os = "linux"), ignore)]
#[test]
fn sgxdevice() {
    #[cfg(target_os = "linux")]
    test_loader!(isgx::Device::new());
}

#[cfg_attr(feature = "no_sgx_enclave_common", ignore)]
#[test]
fn sgx_enclave_common() {
    eprintln!("NOTE: As of September 2020, this loader doesn't support launch tokens, due to missing support in the Intel library.");
    test_loader!(sgx_enclave_common::Library::load(None));
}
