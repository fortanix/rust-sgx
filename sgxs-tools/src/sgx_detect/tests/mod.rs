use std::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;
use std::io::ErrorKind;
use std::io::Error as IoError;

use failure::Error;
use petgraph::visit::EdgeRef;

use enclave_runner::EnclaveBuilder;
use report_test::ReportBuilder;
use sgx_isa::{Attributes, AttributesFlags, Miscselect, Sigstruct};
use sgxs::loader::Load;

mod debug;
#[macro_use]
mod scaffold;

pub use self::scaffold::*;
use crate::interpret::*;
use crate::{DetectError, SgxSupport};
use sgxs_tools::*;

#[derive(Default, DebugSupport, Print, Update)]
struct Root;

#[derive(Default, DebugSupport, Update)]
struct Isa {
    cpu: Status,
    cpu_cfg: Status,
    attr: Status,
    epc: Status,
}

impl Print for Isa {
    fn supported(&self) -> Status {
        self.cpu & self.cpu_cfg & self.attr & self.epc
    }
}

#[optional_inner]
#[derive(Clone)]
struct SgxCpuSupport {
    sgx: Result<bool, Rc<Error>>,
}

impl Update for SgxCpuSupport {
    fn update(&mut self, support: &SgxSupport) {
        self.inner = Some(SgxCpuSupportInner {
            sgx: support.cpuid_7h.as_ref().map(|c| c.sgx).map_err(Rc::clone),
        });
    }
}

impl Print for SgxCpuSupport {
    fn supported(&self) -> Status {
        match self.inner {
            Some(SgxCpuSupportInner { sgx: Ok(true) }) => Status::Supported,
            _ => Status::Fatal,
        }
    }
}

#[optional_inner]
#[derive(Clone, Update)]
struct SgxCpuConfiguration {
    sgx1: bool,
    enclave_size_ok: bool,
    sgx2: bool,
    exinfo: bool,
    enclv: bool,
    oversub: bool,
    cpuid_err: Option<Rc<Error>>,
    msr_3ah: Result<Msr3ah, Rc<Error>>,
    efi_epcbios: Result<EfiEpcbios, Rc<Error>>,
    efi_epcsw: Result<EfiEpcsw, Rc<Error>>,
    efi_status: Result<EfiSoftwareguardstatus, Rc<Error>>,
}

#[dependency]
impl Dependency<SgxCpuSupport> for SgxCpuConfiguration {
    const CONTROL_VISIBILITY: bool = true;

    fn update_dependency(&mut self, dependency: &SgxCpuSupport, support: &SgxSupport) {
        self.inner = match dependency.inner {
            Some(SgxCpuSupportInner { sgx: Ok(v) }) => Some({
                let sgx1;
                let enclave_size_ok;
                let sgx2;
                let exinfo;
                let enclv;
                let oversub;
                let cpuid_err;

                match (v, &support.cpuid_12h_0) {
                    (true, Ok(c)) => {
                        sgx1 = c.sgx1;
                        // Minimum useful enclave size: 2 REG + 1 TCS
                        enclave_size_ok = c.max_enclave_size_32 >= 0x3000 && c.max_enclave_size_64 >= 0x3000;
                        sgx2 = c.sgx2;
                        exinfo = c.miscselect_valid.contains(Miscselect::EXINFO);
                        enclv = c.enclv;
                        oversub = c.oversub;
                        cpuid_err = if sgx1 {
                            None
                        } else {
                            Some(Rc::new(format_err!("CPUID.(EAX=12H,ECX=0):EAX.SGX1 [bit 0] = 0")))
                        };
                    },
                    (sgx, cpuid12) => {
                        sgx1 = false;
                        enclave_size_ok = false;
                        sgx2 = false;
                        exinfo = false;
                        enclv = false;
                        oversub = false;
                        cpuid_err = Some(if sgx {
                            cpuid12.as_ref().unwrap_err().clone()
                        } else {
                            Rc::new(format_err!("SGX not supported"))
                        })
                    }
                }

                SgxCpuConfigurationInner {
                    sgx1,
                    enclave_size_ok,
                    sgx2,
                    exinfo,
                    enclv,
                    oversub,
                    cpuid_err,
                    msr_3ah: support.msr_3ah.clone(),
                    efi_epcbios: support.efi_epcbios.clone(),
                    efi_epcsw: support.efi_epcsw.clone(),
                    efi_status: support.efi_softwareguardstatus.clone(),
                }
            }),
            _ => None,
        };
    }
}

impl Print for SgxCpuConfiguration {
    fn supported(&self) -> Status {
        self.inner.as_ref().map(|inner| inner.sgx1 && inner.enclave_size_ok).as_req()
    }
}

#[optional_inner]
#[derive(Clone, Update)]
struct EnclaveAttributes {
    standard_attributes: bool,
    cpuid_12h_1: Result<Cpuid12h1, Rc<Error>>
}

#[dependency]
impl Dependency<SgxCpuSupport> for EnclaveAttributes {
    const CONTROL_VISIBILITY: bool = true;

    fn update_dependency(&mut self, dependency: &SgxCpuSupport, support: &SgxSupport) {
        self.inner = match (&dependency.inner, &support.cpuid_12h_1) {
            (Some(SgxCpuSupportInner { sgx: Ok(true) }), Ok(c)) => Some(EnclaveAttributesInner {
                standard_attributes: c.attributes_flags_valid.contains(
                    AttributesFlags::DEBUG
                        | AttributesFlags::MODE64BIT
                        | AttributesFlags::PROVISIONKEY
                        | AttributesFlags::EINITTOKENKEY,
                ) && (c.attributes_xfrm_valid & 0x3) == 0x3,
                cpuid_12h_1: Ok(*c),
            }),
            (Some(_), c) => Some(EnclaveAttributesInner {
                standard_attributes: false,
                cpuid_12h_1: c.clone(),
            }),
            (None, _) => None,
        };
    }
}

#[dependency]
impl Dependency<SgxCpuConfiguration> for EnclaveAttributes {
    const CONTROL_VISIBILITY: bool = true;
}

impl Print for EnclaveAttributes {
    fn supported(&self) -> Status {
        self.inner.as_ref().map(|inner| inner.standard_attributes).as_req()
    }
}

#[optional_inner]
#[derive(Clone, Update)]
struct EnclavePageCache {
    total_size: u64,
    any_unknown: bool,
    cpuid_12h_epc: Result<Vec<Cpuid12hEnum>, Rc<Error>>,
}

#[dependency]
impl Dependency<SgxCpuSupport> for EnclavePageCache {
    const CONTROL_VISIBILITY: bool = true;

    fn update_dependency(&mut self, dependency: &SgxCpuSupport, support: &SgxSupport) {
        self.inner = match (&dependency.inner, &support.cpuid_12h_epc) {
            (Some(SgxCpuSupportInner { sgx: Ok(true) }), Ok(c)) => {
                let mut total_size = 0;
                let mut any_unknown = false;
                for section in c {
                    match section {
                        Cpuid12hEnum::Epc {
                            ty: EpcType::ConfidentialityIntegrityProtected,
                            phys_size,
                            ..
                        } => total_size += phys_size,
                        Cpuid12hEnum::Invalid => unreachable!(),
                        _ => any_unknown = true,
                    }
                }

                Some(EnclavePageCacheInner {
                    total_size,
                    any_unknown,
                    cpuid_12h_epc: Ok(c.clone())
                })
            },
            (Some(_), c) => Some(EnclavePageCacheInner {
                total_size: 0,
                any_unknown: true,
                cpuid_12h_epc: c.clone()
            }),
            _ => None,
        };
    }
}

#[dependency]
impl Dependency<SgxCpuConfiguration> for EnclavePageCache {
    const CONTROL_VISIBILITY: bool = true;
}

impl Print for EnclavePageCache {
    fn supported(&self) -> Status {
        match self.inner {
            // Minimum useful EPC size: 1 VA + 1 SECS + 2 REG + 1 TCS
            Some(EnclavePageCacheInner { total_size, .. }) if total_size >= 0x5000 => {
                Status::Supported
            }
            Some(EnclavePageCacheInner {
                any_unknown: true, ..
            }) => Status::Unknown,
            Some(_) => Status::Fatal,
            _ => Status::Unknown,
        }
    }
}

#[derive(Default, DebugSupport, Print, Update)]
struct SgxFeaturesCat;

#[derive(Default, DebugSupport, Update)]
struct SgxFeatures {
    cpu_cfg: Option<SgxCpuConfigurationInner>,
}

#[dependency]
impl Dependency<SgxCpuConfiguration> for SgxFeatures {
    const CONTROL_VISIBILITY: bool = true;

    fn update_dependency(&mut self, dependency: &SgxCpuConfiguration, _support: &SgxSupport) {
        self.cpu_cfg = dependency.inner.clone();
    }
}

#[dependency]
impl Dependency<EnclaveAttributes> for SgxFeatures {
    fn update_dependency(&mut self, _dependency: &EnclaveAttributes, _support: &SgxSupport) {
        // TODO: KSS support from attributes
    }
}

impl Print for SgxFeatures {
    // used for visibility control
    fn try_supported(&self) -> Option<Status> {
        Some(self.cpu_cfg.as_ref().map(|c| c.sgx1).as_req())
    }

    fn print(&self, level: usize) {
        print!(
            "{:width$}{}SGX2  ",
            "",
            self.cpu_cfg.as_ref().map(|c| c.sgx2).as_opt().paint(),
            width = level * 2
        );
        print!(
            "{}EXINFO  ",
            self.cpu_cfg.as_ref().map(|c| c.exinfo).as_opt().paint()
        );
        print!("{}ENCLV  ", self.cpu_cfg.as_ref().map(|c| c.enclv).as_opt().paint());
        println!(
            "{}OVERSUB  ",
            self.cpu_cfg.as_ref().map(|c| c.oversub).as_opt().paint()
        );
        //println!("{}KSS", ...);
    }
}

#[derive(Clone, Default, DebugSupport, Update)]
struct EpcSize {
    epc: Option<EnclavePageCacheInner>,
}

#[dependency]
impl Dependency<EnclavePageCache> for EpcSize {
    const CONTROL_VISIBILITY: bool = true;

    fn update_dependency(&mut self, dependency: &EnclavePageCache, _support: &SgxSupport) {
        // TODO get potentially higher EPC size from EFI
        self.epc = dependency.inner.clone();
    }
}

impl Print for EpcSize {
    fn try_supported(&self) -> Option<Status> {
        None
    }

    fn print(&self, level: usize) {
        if let Some(epc) = &self.epc {
            println!(
                "{:width$}{}: {:.1}MiB",
                "",
                self.name(),
                epc.total_size as f64 / (1048576.),
                width = level * 2
            );
        }
    }
}

#[derive(Default, DebugSupport, Update)]
struct Flc {
    cpu: Status,
    cpu_cfg: Status,
    run_enclave: Status,
}

impl Print for Flc {
    fn supported(&self) -> Status {
        let works = match self.cpu_cfg {
            // if we couldn't probe the msr, run status is leading
            Status::Unknown => self.run_enclave,
            _ => self.cpu_cfg & self.run_enclave
        };
        (self.cpu & works).downgrade_fatal()
    }
}

#[dependency]
impl Dependency<SgxCpuSupport> for Flc {
    const CONTROL_VISIBILITY: bool = true;
}

#[optional_inner]
#[derive(Copy, Clone, Default, DebugSupport, Update)]
struct FlcCpuSupport {
    sgx_lc: bool,
}

#[dependency]
impl Dependency<SgxCpuSupport> for FlcCpuSupport {
    fn update_dependency(&mut self, dependency: &SgxCpuSupport, support: &SgxSupport) {
        self.inner = match (&dependency.inner, &support.cpuid_7h) {
            (Some(SgxCpuSupportInner { sgx: Ok(true) }), Ok(c)) => {
                Some(FlcCpuSupportInner { sgx_lc: c.sgx_lc })
            }
            _ => None,
        };
    }
}

impl Print for FlcCpuSupport {
    fn supported(&self) -> Status {
        self.inner.map(|inner| inner.sgx_lc).as_req()
    }
}

#[derive(Clone, Default, Update)]
struct FlcCpuConfiguration {
    sgx_conf: Status,
    msr_3ah: Option<Result<Msr3ah, Rc<Error>>>
}

#[dependency]
impl Dependency<FlcCpuSupport> for FlcCpuConfiguration {
    const CONTROL_VISIBILITY: bool = true;

    fn update_dependency(&mut self, dependency: &FlcCpuSupport, support: &SgxSupport) {
        self.msr_3ah = match dependency.inner {
            Some(FlcCpuSupportInner { sgx_lc: true }) => Some(support.msr_3ah.clone()),
            _ => None,
        };
    }
}

#[dependency]
impl Dependency<SgxCpuConfiguration> for FlcCpuConfiguration {
    fn update_dependency(&mut self, dependency: &SgxCpuConfiguration, _support: &SgxSupport) {
        self.sgx_conf = dependency.supported();
    }
}

impl Print for FlcCpuConfiguration {
    fn supported(&self) -> Status {
        match self.msr_3ah {
            Some(Err(_)) => Status::Unknown,
            Some(Ok(Msr3ah {
                locked: true,
                sgx_lc: true,
                ..
            })) => Status::Supported,
            Some(Ok(_)) | None => Status::Fatal,
        }
    }
}

#[derive(Default, DebugSupport, Update)]
struct RunEnclaveProdWrap {
    inner: Status,
}

#[dependency]
impl Dependency<SgxCpuSupport> for RunEnclaveProdWrap {
    const CONTROL_VISIBILITY: bool = true;
}

#[dependency]
impl Dependency<FlcCpuSupport> for RunEnclaveProdWrap {
    const CONTROL_VISIBILITY: bool = true;
}

#[dependency]
impl Dependency<FlcCpuConfiguration> for RunEnclaveProdWrap {
    const CONTROL_VISIBILITY: bool = true;
}

#[dependency]
impl Dependency<RunEnclaveProd> for RunEnclaveProdWrap {
    fn update_dependency(&mut self, dependency: &RunEnclaveProd, _support: &SgxSupport) {
        self.inner = dependency.supported();
    }
}

impl Print for RunEnclaveProdWrap {
    fn supported(&self) -> Status {
        self.inner
    }
}

#[derive(Default, DebugSupport, Update)]
struct Psw {
    flc: Status,
    aesm: Status,
    driver: Status,
    encllib: Status,
    run_enclave: Status,
}

#[dependency]
impl Dependency<Flc> for Psw {
    fn update_dependency(&mut self, dependency: &Flc, _support: &SgxSupport) {
        self.flc = dependency.supported();
    }
}

impl Print for Psw {
    fn supported(&self) -> Status {
        let einittoken_provider = self.flc | self.aesm;
        let loader = self.driver | self.encllib;
        einittoken_provider & loader & self.run_enclave
    }
}

#[optional_inner]
#[derive(Clone)]
struct AesmService {
    service: Result<(), Rc<Error>>,
    install_state: Option<AesmStatus>,
}

impl Update for AesmService {
    fn update(&mut self, support: &SgxSupport) {
        self.inner = Some(AesmServiceInner {
            service: match support.aesm_service {
                Ok(_) => Ok(()),
                Err(ref e) => Err(e.clone()),
            },
            install_state: support.aesm_status,
        });
    }
}

impl Print for AesmService {
    fn supported(&self) -> Status {
        self.inner.as_ref().map(|inner| inner.service.is_ok()).as_req()
    }
}

#[optional_inner]
#[derive(Clone)]
struct DeviceLoader {
    devpath: Result<PathBuf, Rc<Error>>,
    modstatus: Result<KmodStatus, Rc<Error>>,
}

impl Update for DeviceLoader {
    fn update(&mut self, support: &SgxSupport) {
        self.inner = Some(DeviceLoaderInner {
            #[cfg(unix)]
            devpath: match support.loader_sgxdev {
                Ok(ref dev) => Ok(dev.borrow().path().to_owned()),
                Err(ref e) => Err(e.clone()),
            },
            #[cfg(windows)]
            devpath: Err(Rc::new(IoError::new(ErrorKind::NotFound, "Device Driver Path not supported in Windows").into())),
            modstatus: support.sgxdev_status.clone()
        });
    }
}

impl Print for DeviceLoader {
    fn supported(&self) -> Status {
        self.inner.as_ref().map(|inner| inner.devpath.is_ok()).as_req()
    }

    fn print(&self, level: usize) {
        print!("{:width$}{}{}", "", self.supported().paint(), self.name(), width = level * 2);
        if let Some(DeviceLoaderInner { devpath: Ok(ref path), .. }) = self.inner {
            print!(" ({})", path.display());
        }
        println!("");
    }
}

#[optional_inner]
#[derive(Copy, Clone, Default, DebugSupport)]
struct EncllibLoader {
    loader_ok: bool,
}

impl Update for EncllibLoader {
    fn update(&mut self, support: &SgxSupport) {
        self.inner = Some(EncllibLoaderInner {
            loader_ok: support.loader_encllib.is_ok(),
        });
    }
}

impl Print for EncllibLoader {
    fn supported(&self) -> Status {
        self.inner.map(|inner| inner.loader_ok).as_req()
    }
}

#[derive(Default, DebugSupport, Update)]
struct RunEnclave {
    debug: Status,
    prod_wl: Status,
    prod: Status,
}

#[dependency]
impl Dependency<AnyLoader> for RunEnclave {
    const CONTROL_VISIBILITY: bool = true;
}

#[dependency]
impl Dependency<AnyTokenProvider> for RunEnclave {
    const CONTROL_VISIBILITY: bool = true;
}

impl Print for RunEnclave {
    fn supported(&self) -> Status {
        self.debug & (self.prod | self.prod_wl)
    }
}

#[derive(Default, DebugSupport, Update)]
struct AnyLoader {
    driver: Status,
    encllib: Status,
}

#[dependency]
impl Dependency<DeviceLoader> for AnyLoader {
    fn update_dependency(&mut self, dependency: &DeviceLoader, _support: &SgxSupport) {
        self.driver = dependency.supported();
    }
}

#[dependency]
impl Dependency<EncllibLoader> for AnyLoader {
    fn update_dependency(&mut self, dependency: &EncllibLoader, _support: &SgxSupport) {
        self.encllib = dependency.supported();
    }
}

impl Name for AnyLoader {
    fn name(&self) -> &'static str {
        "Any enclave loader"
    }
}

impl Print for AnyLoader {
    fn supported(&self) -> Status {
        self.driver | self.encllib
    }
}

#[derive(Default, DebugSupport, Update)]
struct AnyTokenProvider {
    flc_conf: Status,
    aesm: Status,
}

#[dependency]
impl Dependency<FlcCpuConfiguration> for AnyTokenProvider {
    fn update_dependency(&mut self, dependency: &FlcCpuConfiguration, _support: &SgxSupport) {
        self.flc_conf = dependency.supported();
    }
}

#[dependency]
impl Dependency<AesmService> for AnyTokenProvider {
    fn update_dependency(&mut self, dependency: &AesmService, _support: &SgxSupport) {
        self.aesm = dependency.supported();
    }
}

impl Name for AnyTokenProvider {
    fn name(&self) -> &'static str {
        "Any EINITTOKEN provider (or FLC)"
    }
}

impl Print for AnyTokenProvider {
    fn supported(&self) -> Status {
        self.flc_conf | self.aesm
    }
}

macro_rules! define_run_enclave {
    ($ty:ident) => {
        #[derive(Default)]
        struct $ty {
            cpu_conf: Option<Status>,
            loader: Option<Status>,
            tokenprov: Option<Status>,
            success: Option<Result<(), Error>>,
        }

        #[dependency]
        impl Dependency<SgxCpuConfiguration> for $ty {
            fn update_dependency(&mut self, dependency: &SgxCpuConfiguration, support: &SgxSupport) {
                self.cpu_conf = Some(dependency.supported());
                self.update(support);
            }
        }

        #[dependency]
        impl Dependency<AnyLoader> for $ty {
            fn update_dependency(&mut self, dependency: &AnyLoader, support: &SgxSupport) {
                self.loader = Some(dependency.supported());
                self.update(support);
            }
        }

        #[dependency]
        impl Dependency<AnyTokenProvider> for $ty {
            fn update_dependency(&mut self, dependency: &AnyTokenProvider, support: &SgxSupport) {
                self.tokenprov = Some(dependency.supported());
                self.update(support);
            }
        }

        impl Update for $ty {
            fn update(&mut self, support: &SgxSupport) {
                if self.cpu_conf == Some(Status::Supported)
                    && self.loader == Some(Status::Supported)
                    && self.tokenprov != Some(Status::Fatal) // loader might be `Unknown` if FLC is enabled
                {
                    if let Ok(ref loader) = support.loader_sgxdev {
                        self.success = Some(Self::try_loader(&mut*loader.borrow_mut()));
                        if self.success.as_ref().map_or(false, |res| res.is_ok()) {
                            return
                        }
                    }
                    if let Ok(ref loader) = support.loader_encllib {
                        let result = Self::try_loader(&mut*loader.borrow_mut());
                        if result.is_ok() || self.success.is_none() {
                            self.success = Some(result);
                        }
                        if self.success.as_ref().map_or(false, |res| res.is_ok()) {
                            return
                        }
                    }
                    if self.success.is_none() {
                        self.success = Some(Err(format_err!("No loader available")))
                    }
                } else {
                    self.success = None
                }
            }
        }

        impl Print for $ty {
            fn supported(&self) -> Status {
                self.success.as_ref().map_or(Status::Unknown, |res| res.is_ok().as_req())
            }
        }
    }
}

define_run_enclave!(RunEnclaveDebug);

impl RunEnclaveDebug {
    fn try_loader<L: Load>(enclave_loader: &mut L) -> Result<(), Error> {
        let tinfo = Default::default();
        ReportBuilder::new(&tinfo)
            .build(enclave_loader)?;
        Ok(())
    }
}

define_run_enclave!(RunEnclaveProdWl);

impl RunEnclaveProdWl {
    fn try_loader<L: Load>(enclave_loader: &mut L) -> Result<(), Error> {
        let enclave = include_bytes!("test_enclave.sgxs");
        let sig = include_bytes!("test_enclave.sig");
        let sig = Sigstruct::try_copy_from(sig).unwrap();

        let mut builder = EnclaveBuilder::new_from_memory(enclave);
        builder.attributes(sig.attributes).sigstruct(sig);

        let lib = builder.build_library(enclave_loader)?;

        unsafe {
            match lib.call(!0, 0, 0, 0, 0) {
                Err(ref e) if e.to_string().contains("The enclave performed an invalid usercall 0x") => Ok(()),
                Err(e) => Err(e.into()),
                Ok(_) => Err(format_err!("Unexpected enclave return value")),
            }
        }
    }
}

#[dependency]
impl Dependency<RunEnclaveDebug> for RunEnclaveProdWl {
    const CONTROL_VISIBILITY: bool = true;
}

define_run_enclave!(RunEnclaveProd);

impl RunEnclaveProd {
    fn try_loader<L: Load>(enclave_loader: &mut L) -> Result<(), Error> {
        let tinfo = Default::default();
        ReportBuilder::new(&tinfo)
            .attributes(Attributes { flags: AttributesFlags::empty(), xfrm: 3 })
            .build(enclave_loader)?;
        Ok(())
    }
}

#[dependency]
impl Dependency<FlcCpuSupport> for RunEnclaveProd {
    const CONTROL_VISIBILITY: bool = true;
}

#[dependency]
impl Dependency<RunEnclaveProdWl> for RunEnclaveProd {
    const CONTROL_VISIBILITY: bool = true;
}

impl Tests {
    fn print_recurse(&self, test: TypeIdIdx, level: usize, path: &mut Vec<TypeIdIdx>, debug: &mut Vec<Vec<TypeIdIdx>>) {
        if self
            .dependencies
            .edges_directed(test.into(), petgraph::Direction::Incoming)
            .any(|edge| edge.weight().hidden.get())
        {
            return;
        }
        if let Some(adj_level) = level.checked_sub(1) {
            self.functions[test].print(adj_level);
            match self.functions[test].try_supported() {
                None | Some(Status::Supported) => {},
                _ => debug.push(path.clone()),
            }
        }
        for child in self
            .ui_children
            .get(test as usize)
            .cloned()
            .unwrap_or_default()
        {
            path.push(child);
            self.print_recurse(child, level + 1, path, debug);
            path.pop();
        }
    }

    pub fn print(&self, verbose: bool) {
        let mut debug = vec![];
        self.print_recurse(self.ui_root, 0, &mut vec![], &mut debug);
        for path in debug {
            let test = *path.last().unwrap();
            let path = path.into_iter().map(|test| self.functions[test].name()).collect();
            let out = debug::Output::new(path, verbose);
            let _ = self.functions[test].debug(out, &self.functions);
        }

        if self.functions.lookup::<Isa>().supported() &
            self.functions.lookup::<Psw>().supported() == Status::Supported {
            println!("\nYou're all set to start running SGX programs!");
        }
    }

    pub fn check_support(&mut self, support: &SgxSupport) {
        fn slice_dual_access<T>(slice: &mut [T], idx1: usize, idx2: usize) -> (&mut T, &mut T) {
            assert_ne!(idx1, idx2);
            if idx1 < idx2 {
                let (a, b) = slice.split_at_mut(idx1 + 1);
                (&mut a[idx1], &mut b[idx2 - idx1 - 1])
            } else {
                let (a, b) = slice.split_at_mut(idx2 + 1);
                (&mut b[idx1 - idx2 - 1], &mut a[idx2])
            }
        }

        let mut topovisit = petgraph::visit::Topo::new(&self.dependencies);
        while let Some(node) = topovisit.next(&self.dependencies) {
            if self
                .dependencies
                .edges_directed(node, petgraph::Direction::Incoming)
                .next()
                .is_none()
            {
                self.functions[node.index() as _].update(support);
            }

            for edge in self
                .dependencies
                .edges_directed(node, petgraph::Direction::Outgoing)
            {
                assert_eq!(edge.source(), node);
                let dependency_idx = edge.source().index();
                let dependent_idx = edge.target().index();
                let depinfo = edge.weight();

                let (dependency, dependent) =
                    slice_dual_access(self.functions.as_slice_mut(), dependency_idx, dependent_idx);

                (depinfo.update_fn)(&**dependency, &mut **dependent, support, &depinfo.hidden);
            }
        }
    }
}

impl Tests {
    pub fn new() -> Tests {
        let mut tests = tests! {
            "SGX instruction set" => Category(Isa, tests: {
                @[update_supported = cpu]
                "CPU support" => Test(SgxCpuSupport),
                @[update_supported = cpu_cfg]
                "CPU configuration" => Test(SgxCpuConfiguration),
                @[update_supported = attr]
                "Enclave attributes" => Test(EnclaveAttributes),
                @[update_supported = epc]
                "Enclave Page Cache" => Test(EnclavePageCache),
                "SGX features" => Category(SgxFeaturesCat, tests: {
                    @[control_visibility]
                    "SGX features" => Test(SgxFeatures),
                    "Total EPC size" => Test(EpcSize),
                }),
            }),
            "Flexible launch control" => Category(Flc, tests: {
                @[update_supported = cpu]
                "CPU support" => Test(FlcCpuSupport),
                @[update_supported = cpu_cfg]
                "CPU configuration" => Test(FlcCpuConfiguration),
                @[update_supported = run_enclave]
                "Able to launch production mode enclave" => Test(RunEnclaveProdWrap),
            }),
            "SGX system software" => Category(Psw, tests: {
                @[update_supported = driver]
                "SGX kernel device" => Test(DeviceLoader),
                @[update_supported = encllib]
                "libsgx_enclave_common" => Test(EncllibLoader),
                @[update_supported = aesm]
                "AESM service" => Test(AesmService),
                @[update_supported = run_enclave]
                "Able to launch enclaves" => Category(RunEnclave, tests: {
                    @[update_supported = debug]
                    "Debug mode" => Test(RunEnclaveDebug),
                    @[update_supported = prod]
                    "Production mode" => Test(RunEnclaveProd),
                    @[update_supported = prod_wl]
                    "Production mode (Intel whitelisted)" => Test(RunEnclaveProdWl),
                }),
            }),
            //Category {
            //    name: "SGX remote attestation",
            //    items: vec![
            //        AttestationEpid.into(),
            //        AttestationDcap.into(),
            //    ],
            //    post: None
            //},
        };

        let fns = &mut tests.functions;
        tests
            .dependencies
            .extend_with_edges(DEPENDENCIES.iter().map(|&(n1, f1, n2, f2, update_fn)| {
                (
                    fns.allocate_raw(n1(), f1),
                    fns.allocate_raw(n2(), f2),
                    DependencyInfo {
                        update_fn,
                        hidden: Cell::new(false),
                    },
                )
            }));

        assert!(!petgraph::algo::is_cyclic_directed(&tests.dependencies));
        assert_eq!(petgraph::algo::connected_components(&tests.dependencies), 1);

        tests
    }
}

fn update<T: DetectItem, U: Dependency<T>>(
    dependency: &dyn DetectItem,
    dependent: &mut dyn DetectItem,
    support: &SgxSupport,
    hidden: &Cell<bool>,
) {
    let dependent = dependent.downcast_mut::<U>().unwrap();
    let dependency = dependency.downcast_ref::<T>().unwrap();
    dependent.update_dependency(dependency, support);

    let hiddenval = if U::CONTROL_VISIBILITY {
        dependency.try_supported() == Some(Status::Fatal)
    } else {
        false
    };
    hidden.set(hiddenval);
}

fn default<T: DetectItem>() -> Box<dyn DetectItem> {
    T::default()
}

define_dependencies!(default, DetectItemInitFn, update, DependencyUpdateFn);

#[cfg(test)]
mod tests {
    #[test]
    /// Test whether `Tests` can be constructed, and in particular if the
    /// dependency graph is a DAG.
    fn construct_tests() {
        super::Tests::new();
    }
}
