//! Functions here support the interaction with a debugger such as gdb.
//!
//! The `ftxsgx_get_baseaddress_from_pointer` function is the main intended entrypoint,
//! it can be called statically by gdb on a running ftxsgx-loader,
//! or on your binary if this crate is used as a library.

use std::sync::Mutex;
use std::sync::OnceLock;

/// Stores an Enclave's baseaddress and size.
/// We need to keep track of existing Enclaves for debugging,
/// to be able to find the baseaddress and the enclave given a global pointer.
struct EnclaveBaseAddress {
    baseaddress: u64,
    size: u64,
}

/// A (cached) registry of currently running enclaves.
///
/// Note that the list, at any moment in time, might be outdated:
/// * a recently started Enclave might not have been registered yet,
/// * and an enclave that have finished might not have been unregistered yet.
///
/// The only allowed way to use this is thus informational, without reliance on correctness.
/// It is currently used for debugging (see gdb.py).
#[derive(Default)]
struct EnclaveRegistry {
    enclaves: Vec<EnclaveBaseAddress>,
}

/// A global, static mutex to the EnclaveRegistry.
///
/// Global statics are (obviously) an anti-pattern.
/// Here, we're choosing to use a global/static because the data from the registry
/// will be requested by gdb, globally, without parameters, on a running process.
fn enclave_registry_mutex() -> &'static Mutex<EnclaveRegistry> {
    static BASEADDRESS_MUTEX: OnceLock<Mutex<EnclaveRegistry>> = OnceLock::new();
    BASEADDRESS_MUTEX.get_or_init(|| Mutex::new(EnclaveRegistry::default()))
}

pub fn register_new_enclave(baseaddress: u64, size: u64) {
    enclave_registry_mutex()
        .lock()
        .expect("Failed to obtain enclave registry mutex for new enclave")
        .enclaves
        .push(EnclaveBaseAddress { baseaddress, size });
    // This is not much of a correctness check per se, but this ensures
    // that the `ftxsgx_get_baseaddress_from_pointer` function is not eliminated during compilation,
    // even in --release mode. See the documentation for that function on why we need this.
    assert_eq!(
        ftxsgx_get_baseaddress_from_pointer(baseaddress),
        baseaddress
    );
}

pub fn unregister_terminated_enclave(baseaddress: u64) {
    enclave_registry_mutex()
        .lock()
        .expect("Failed to obtain an enclave registry mutex for termination")
        .enclaves
        .retain(|e| e.baseaddress != baseaddress)
}

/// This function should be accessible by gdb, even if compiled in --release mode.
/// Same as with the Mutex function above, this needs to be
/// a global/static because it will be called by gdb, globally, without parameters.
#[no_mangle]
#[inline(never)]
pub extern "C" fn ftxsgx_get_baseaddress_from_pointer(gdb_pointer: u64) -> u64 {
    let registry = enclave_registry_mutex()
        .lock()
        .expect("Failed to obtain enclave registry mutex for calculating the baseaddress");
    let found = registry
        .enclaves
        .iter()
        .find(|e| e.baseaddress <= gdb_pointer && gdb_pointer < e.baseaddress + e.size);
    found.map(|enclave| enclave.baseaddress).unwrap_or(0)
}
