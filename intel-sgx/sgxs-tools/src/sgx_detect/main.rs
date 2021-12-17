//! sgx-detect: An SGX configuration detection and verification tool.
//!
//! This tool is mainly implemented in three phases.
//!
//! # `SgxSupport::detect`
//! Probes the environment for things that can be determined relatively
//! quickly: CPUID, MSRs, environment variables, dynamic libraries, etc.
//! This step does not access the network (but AESM may access the network at
//! this time) or make any changes to the system.
//!
//! # `Tests::check_support`
//! Several types implementing `trait DetectItem` are statically defined in the
//! source code. These items represent functionality determination logic such
//! as “does the CPU support SGX” and “is the SGX driver installed”.
//! Dependencies between the items are defined using the `Dependency` trait,
//! which should be a directed acyclic graph.
//!
//! This function walks the dependency tree, starting with the items without
//! dependencies, recording whether a particular item is supported or not. When
//! an item is updated, its dependents are notified of the new state. If an
//! item is not supported, printing of its dependencies may be hidden (see next
//! step).
//!
//! # `Tests::print`
//! Walks the UI tree (a *different* tree from the dependency tree), printing
//! the status of each item. If any dependencies declared that an item should
//! be hidden, it and its children are not printed.
//!
//! After the UI tree is printed, any items that were printed that were not
//! supported may print debug information to guide the user on how to fix that
//! item. The debugging may occur interactively.

#[macro_use]
extern crate log;
#[macro_use]
extern crate failure;
#[macro_use]
extern crate failure_derive;
#[macro_use]
extern crate mopa;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate clap;

use std::arch::x86_64::{self, CpuidResult};
use std::cell::{Cell, RefCell};
use std::ffi::{OsStr, OsString};
use std::{fmt, str};
use std::fs::File;
use std::rc::Rc;
use std::process::Command;
use std::io::{self, BufRead, Error as IOError, ErrorKind};
use reqwest;
use failure::Error;
use yansi::Paint;
use aesm_client::AesmClient;
use sgx_isa::{Sigstruct, Attributes, Einittoken};
use sgxs::einittoken::EinittokenProvider;
#[cfg(unix)]
use sgxs_loaders::isgx::Device as SgxDevice;
#[cfg(windows)]
use sgxs_loaders::enclaveapi::Sgx as SgxDevice;
use sgxs_loaders::sgx_enclave_common::Library as EnclCommonLib;
use proc_mounts::MountList;

mod interpret;
#[cfg(windows)]
extern crate winapi;

#[cfg(windows)]
#[path = "imp/windows.rs"]
mod imp;
#[cfg(unix)]
#[path = "imp/linux.rs"]
mod imp;
mod tests;

use crate::interpret::*;
use crate::tests::Tests;

#[derive(Debug, Fail)]
enum DetectError {
    #[fail(display = "CPUID leaf {:x}h is not valid", leaf)]
    CpuidLeafInvalid { leaf: u32 },
    #[fail(display = "Failed access EFI variables")]
    EfiFsError(#[cause] io::Error),
    #[fail(display = "Failed to read EFI variable")]
    EfiVariableError(#[cause] io::Error),
    #[fail(display = "Not available when using JSON tests")]
    NotAvailableInTest,
}

fn cpuid(eax: u32, ecx: u32) -> Result<CpuidResult, Error> {
    unsafe {
        if eax <= x86_64::__get_cpuid_max(0).0 {
            Ok(x86_64::__cpuid_count(eax, ecx))
        } else {
            bail!(DetectError::CpuidLeafInvalid { leaf: eax })
        }
    }
}

mod detect_result {
    use std::rc::Rc;

    use failure::{Error, err_msg};
    use serde::ser::{Serialize, Serializer};
    use serde::de::{Deserialize, Deserializer};

    pub fn serialize<T: Serialize, S: Serializer>(res: &Result<T, Rc<Error>>, serializer: S) -> Result<S::Ok, S::Error> {
        res.as_ref().map_err(|e| e.to_string()).serialize(serializer)
    }

    pub fn deserialize<'de, T: Deserialize<'de>, D: Deserializer<'de>>(deserializer: D) -> Result<Result<T, Rc<Error>>, D::Error> {
        match Result::<T, String>::deserialize(deserializer) {
            Ok(Ok(v)) => Ok(Ok(v)),
            Ok(Err(e)) => Ok(Err(Rc::new(err_msg(e)))),
            Err(e) => Err(e),
        }
    }
}

fn no_deserialize<T>() -> Result<T, Rc<Error>> {
    Err(Rc::new(DetectError::NotAvailableInTest.into()))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SgxSupport {
    #[serde(with = "detect_result")]
    cpuid_7h: Result<Cpuid7h, Rc<Error>>,
    #[serde(with = "detect_result")]
    cpuid_12h_0: Result<Cpuid12h0, Rc<Error>>,
    #[serde(with = "detect_result")]
    cpuid_12h_1: Result<Cpuid12h1, Rc<Error>>,
    #[serde(with = "detect_result")]
    cpuid_12h_epc: Result<Vec<Cpuid12hEnum>, Rc<Error>>,
    #[serde(with = "detect_result")]
    msr_3ah: Result<Msr3ah, Rc<Error>>,
    #[serde(with = "detect_result")]
    efi_epcbios: Result<EfiEpcbios, Rc<Error>>,
    #[serde(with = "detect_result")]
    efi_epcsw: Result<EfiEpcsw, Rc<Error>>,
    #[serde(with = "detect_result")]
    efi_softwareguardstatus: Result<EfiSoftwareguardstatus, Rc<Error>>,
    #[serde(skip, default = "no_deserialize")]
    aesm_service: Result<TimeoutHardError<AesmClient>, Rc<Error>>,
    aesm_status: Option<AesmStatus>,
    #[serde(skip, default)]
    _dcap_library: bool,
    #[serde(skip, default = "no_deserialize")]
    loader_sgxdev: Result<Rc<RefCell<SgxDevice>>, Rc<Error>>,
    #[serde(skip, default = "no_deserialize")]
    sgxdev_status: Result<KmodStatus, Rc<Error>>,
    #[serde(skip, default = "no_deserialize")]
    loader_encllib: Result<Rc<RefCell<EnclCommonLib>>, Rc<Error>>,
    #[serde(with = "detect_result")]
    enclaveos_dev: Result<(), Rc<Error>>,
    #[serde(with = "detect_result")]
    node_agent: Result<NodeAgentVersion, Rc<Error>>,
    #[serde(with = "detect_result")]
    perm_daemon: Result<(), Rc<Error>>,
    env_config: tests::EnvConfig,
}

struct FailTrace<'a>(pub &'a Error);

impl<'a> fmt::Display for FailTrace<'a> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "{}", self.0)?;
        for cause in self.0.iter_causes() {
            write!(fmt, "\ncause: {}", cause)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
struct TimeoutHardError<T> {
    inner: Rc<RefCell<T>>,
    timedout: Rc<Cell<bool>>,
}

impl TimeoutHardError<AesmClient> {
    fn new(inner: AesmClient) -> Self {
        TimeoutHardError {
            inner: Rc::new(RefCell::new(inner)),
            timedout: Rc::default(),
        }
    }
}

impl EinittokenProvider for TimeoutHardError<AesmClient> {
    fn token(
        &mut self,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        retry: bool,
    ) -> Result<Einittoken, Error> {
        if self.timedout.get() {
            Err(io::Error::new(io::ErrorKind::TimedOut, "AESM timed out").into())
        } else {
            let result = self.inner.borrow_mut().token(sigstruct, attributes, retry);
            if let Err(ref e) = result {
                if let Some(aesm_client::Error::AesmCommunication(ref e)) = e.downcast_ref() {
                    match e.kind() {
                        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock => self.timedout.set(true),
                        _ => {},
                    }
                }
            }
            result
        }
    }

    fn can_retry(&self) -> bool {
        false
    }
}

impl SgxSupport {
    fn detect(env_config: tests::EnvConfig) -> Self {
        fn rcerr<T>(v: Result<T, Error>) -> Result<T, Rc<Error>> {
            v.map_err(Rc::new)
        }

        let cpuid_7h = cpuid(0x7, 0).map(Cpuid7h::from);
        let cpuid_12h_0 = cpuid(0x12, 0).map(Cpuid12h0::from);
        let cpuid_12h_1 = cpuid(0x12, 1).map(Cpuid12h1::from);
        let cpuid_12h_epc = (2..)
            .into_iter()
            .map(|n| cpuid(0x12, n).map(|v| Cpuid12hEnum::from((n, v))))
            .take_while(|v| match v {
                Err(_) | Ok(Cpuid12hEnum::Invalid) => false,
                _ => true,
            })
            .collect();
        let msr_3ah = imp::rdmsr(0x3a).map(Msr3ah::from);
        let efi_epcbios = imp::read_efi_var("EPCBIOS", "c60aa7f6-e8d6-4956-8ba1-fe26298f5e87")
            .map(EfiEpcbios::from);
        let efi_epcsw = imp::read_efi_var("EPCSW", "d69a279b-58eb-45d1-a148-771bb9eb5251")
            .map(EfiEpcsw::from);
        let efi_softwareguardstatus = imp::read_efi_var(
            "SOFTWAREGUARDSTATUS",
            "9cb2e73f-7325-40f4-a484-659bb344c3cd",
        )
        .map(EfiSoftwareguardstatus::from);
        let aesm_service = (|| {
            let client = AesmClient::new();
            client.try_connect()?;
            Ok(TimeoutHardError::new(client))
        })();
        let aesm_status = imp::aesm_status().map_err(|e| debug!("{}", FailTrace(&e))).ok();
        #[cfg(unix)]
            let dcap_library = dcap_ql::is_loaded();
        #[cfg(windows)]
            let dcap_library = false;

        let loader_sgxdev = (|| {
            let mut dev = SgxDevice::new()?;
            if let Ok(ref aesm) = aesm_service {
                dev = dev.einittoken_provider(aesm.clone());
            }
            let device = dev.build();
            if let Ok(mount_list) = MountList::new() {
                let mut path = device.path();
                while let Some(p) = path.parent() {
                    if let Some(mount_info) = mount_list.0.iter().find(|&x| x.dest == p) {
                        if mount_info.options.iter().any(|o| o == "noexec") {
                            return Err(failure::format_err!("{:?} mounted with `noexec` option", mount_info.dest));
                        }
                    }
                    path = p;
                }
            }
            Ok(Rc::new(RefCell::new(device)))
        })();
        let sgxdev_status = imp::kmod_status();
        let loader_encllib = (|| {
            let mut lib = EnclCommonLib::load(None)?;
            if let Ok(ref aesm) = aesm_service {
                lib = lib.einittoken_provider(aesm.clone());
            }
            Ok(Rc::new(RefCell::new(lib.build())))
        })();
        let gsgxdev = (|| -> Result<(), Error> {
            File::open("/dev/gsgx")?;
            Ok(())
        })();
        let nodeagent_status = (|| {
            let mut response = reqwest::get("http://localhost:9092/v1/sys/version")?;
            let ver: NodeAgentVersion = response.json()?;
            Ok(NodeAgentVersion { version: ver.version })
        })();
        let permdaemon_status = (|| -> Result<(), Error> {
            let mut isgx = false;
            let mut gsgx = false;
            let daemon_status = Command::new("systemctl")
                .arg("is-active")
                .arg("sgx_perm_daemon")
                .output()?
                .stdout;
            let daemon_active = str::from_utf8(&daemon_status)?
                .eq("active\n");
            Command::new("journalctl")
                .arg("-u")
                .arg("sgx_perm_daemon")
                .output()?
                .stdout
                .lines()
                .filter_map(|line| line.ok())
                .for_each(|line| {
                if line.contains("gsgx: 10:54") {
                    gsgx = true;
                } else if line.contains("isgx: 10:55"){
                    isgx = true;
                }
            });
            if isgx && gsgx && daemon_active {
                Ok(())
            } else {
                Err(IOError::new(ErrorKind::Other, "[perm_daemon_test] perm daemon is not operational").into())
            }
        })();
        SgxSupport {
            cpuid_7h: rcerr(cpuid_7h),
            cpuid_12h_0: rcerr(cpuid_12h_0),
            cpuid_12h_1: rcerr(cpuid_12h_1),
            cpuid_12h_epc: rcerr(cpuid_12h_epc),
            msr_3ah: rcerr(msr_3ah),
            efi_epcbios: rcerr(efi_epcbios),
            efi_epcsw: rcerr(efi_epcsw),
            efi_softwareguardstatus: rcerr(efi_softwareguardstatus),
            aesm_service: rcerr(aesm_service),
            aesm_status,
            _dcap_library: dcap_library,
            loader_sgxdev: rcerr(loader_sgxdev),
            sgxdev_status: rcerr(sgxdev_status),
            loader_encllib: rcerr(loader_encllib),
            enclaveos_dev: rcerr(gsgxdev),
            node_agent: rcerr(nodeagent_status),
            perm_daemon: rcerr(permdaemon_status),
            env_config,
        }
    }
}

fn paintalt(enabled: &'static str, disabled: &'static str) -> Paint<&'static str> {
    if Paint::is_enabled() {
        Paint::new(enabled)
    } else {
        Paint::new(disabled)
    }
}

fn main() {
    fn readable_file(val: &OsStr) -> Result<(), OsString> {
        match File::open(val) {
            Ok(_) => Ok(()),
            Err(e) => Err(format!("{} while opening file: {}", e, val.to_string_lossy()).into()),
        }
    }

    let args = clap_app!(("sgx-detect") =>
        (author: "Fortanix, Inc.")
        (about: "SGX feature/configuration detection tool")
        (version: crate_version!())
        (@setting UnifiedHelpMessage)
        (@arg TESTFILE: --test   value_name("FILE") validator_os(readable_file) "Read support information in YAML from FILE (instead of from the environment)")
        (@arg EXPORT:   --export                                                "Export detected support information as YAML")
        (@arg PLAIN:    --plaintext                                             "Disable color and UTF-8 output")
        (@arg VERBOSE:  --verbose -v                                            "Print extra information when encountering issues")
        (@group environment_type =>
            (@arg ENCLAVE_OS: --("enclave-os")                                  "Run extra diagnostics tests for EnclaveOS")
            (@arg ENCLAVE_MANAGER: --("enclave-manager")                        "Run extra diagnostics tests for Enclave Manager")
            (@arg DATA_SHIELD: --("data-shield")                                "Run extra diagnostics tests for Data Shield")
        )
    ).get_matches();

    let env_config = if args.is_present("ENCLAVE_OS") {
        tests::EnvConfig::EnclaveOS
    } else if args.is_present("ENCLAVE_MANAGER") {
        tests::EnvConfig::EnclaveManager
    } else if args.is_present("DATA_SHIELD") {
        tests::EnvConfig::DataShield
    } else {
        tests::EnvConfig::Generic
    };

    if args.is_present("PLAIN") || atty::isnt(atty::Stream::Stdout) {
        Paint::disable()
    }
    env_logger::init();

    let mut support = None;

    if let Some(f) = args.value_of_os("TESTFILE") {
        support = Some(serde_yaml::from_reader(File::open(f).unwrap()).unwrap());
    }

    println!("Detecting SGX, this may take a minute...");
    let support = support.unwrap_or_else(|| SgxSupport::detect(env_config));

    if args.is_present("EXPORT") {
        serde_yaml::to_writer(io::stdout(), &support).unwrap();
        println!();
    } else {
        let mut tests = Tests::new();
        tests.check_support(&support);
        tests.print(args.is_present("VERBOSE"), env_config);
    }
}
