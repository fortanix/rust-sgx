use super::*;

use std::borrow::Cow;
use std::fmt::{self, Write as FmtWrite};
use std::io::{self, stdout, Write};

use yansi::{Color, Paint};

use crate::{FailTrace, paintalt};

impl DebugSupport for SgxCpuSupport {
    fn debug(&self, mut out: debug::Output, _items: &DetectItemMap) -> fmt::Result {
        writeln!(out, "It appears your hardware does not have SGX support.")?;
        out.verbose();
        if let Some(SgxCpuSupportInner { sgx: Err(ref e) }) = self.inner {
            writeln!(out, "CPUID error: {}", FailTrace(&e))?;
        } else {
            writeln!(out, "CPUID.(EAX=07H,ECX=0H):EBX.SGX[bit 2] = 0")?;
        }
        out.help_link("cpu-support")
    }
}

impl DebugSupport for SgxCpuConfiguration {
    fn debug(&self, mut out: debug::Output, _items: &DetectItemMap) -> fmt::Result {
        let mut debug_msr = true;
        let help_link;
        
        let inner = self.inner.as_ref().unwrap();

        if inner.sgx1 && !inner.enclave_size_ok {
            help_link = "invalid-cpuid";

            writeln!(out, "Your hardware supports SGX, but the maximum enclave size is misconfigured. This could indicate a CPU or hypervisor bug.")?;

            debug_msr = false;
        } else {
            help_link = "cpu-configuration";
            // try to say something useful about BIOS configuration
            fn is_efi_perm_error(err: &Error) -> bool {
                if let Some(DetectError::EfiVariableError(ioerr)) = err.downcast_ref() {
                    ioerr.kind() == io::ErrorKind::PermissionDenied
                } else {
                    false
                }
            }

            let mut swcontrol_msg = Cow::from("Reboot your machine and try to change the SGX setting from “software controlled” to “enabled”. Alternatively, try updating your BIOS to the latest version or contact your BIOS vendor.");
            if !Paint::is_enabled() {
                swcontrol_msg = swcontrol_msg.replace('“', r#"""#).replace('”', r#"""#).into();
            }
            const SGX_DISABLED: Result<EfiSoftwareguardstatus, Rc<Error>> = Ok(EfiSoftwareguardstatus { status: SgxEnableStatus::Disabled });
            const SGX_ENABLED: Result<EfiSoftwareguardstatus, Rc<Error>> = Ok(EfiSoftwareguardstatus { status: SgxEnableStatus::Enabled });
            const SGX_SWCONTROL: Result<EfiSoftwareguardstatus, Rc<Error>> = Ok(EfiSoftwareguardstatus { status: SgxEnableStatus::SoftwareControlled });
            const SGX_UNKNOWN: Result<EfiSoftwareguardstatus, Rc<Error>> = Ok(EfiSoftwareguardstatus { status: SgxEnableStatus::Unknown });

            writeln!(out, "Your hardware supports SGX, but it's not enabled.\n")?;

            match (&inner.efi_status, &inner.efi_epcbios) {
                (&SGX_DISABLED, _) => {
                    writeln!(out, "Your BIOS supports SGX, but it's disabled. Reboot your machine and enable SGX in your BIOS.")?;
                    debug_msr = false;
                },
                (&SGX_ENABLED, _) => {
                    writeln!(out, "Your BIOS says it supports SGX and SGX is enabled, but it's not. Try updating your BIOS to the latest version or contact your BIOS vendor.")?;
                },
                (&SGX_SWCONTROL, Err(e)) if is_efi_perm_error(&e) => {
                    writeln!(out, "Your BIOS says it supports SGX reconfiguration, but the control mechanism could not be accessed due to a permission issue.")?;
                    writeln!(out, "\nWould you like to re-run this program with sudo to try again?\n{}", Paint::red("(not supported yet)"))?; //TODO
                }
                (&SGX_SWCONTROL, Err(_)) => {
                    write!(out, "Your BIOS says it supports SGX reconfiguration, but there is a problem with the control mechanism.")?;
                    writeln!(out, "{}", swcontrol_msg)?;
                },
                (_, Ok(epcbios)) => {
                    if epcbios.current_epc_size > 0 {
                        write!(out, "Your BIOS says it supports SGX and SGX is enabled, but it's not.")?;
                        writeln!(out, "{}", swcontrol_msg)?;
                    } else if epcbios.max_epc_size > 0 {
                        match inner.efi_epcsw {
                            Ok(EfiEpcsw { epc_size: 0 }) | Err(_) => {
                                writeln!(out, "Your BIOS supports SGX but it's currently disabled.\n\nWould you like to enable SGX automatically after the next reboot?\n{}", Paint::red("(not supported yet)"))?; //TODO
                            },
                            Ok(_) => {
                                writeln!(out, "Your BIOS supports SGX but it's currently disabled. However, it's configured to enabled SGX automatically after the next reboot.")?;
                            }
                        }
                        debug_msr = false;
                    } else {
                        write!(out, "Your BIOS says it supports SGX reconfiguration, but there is a problem with the control mechanism.")?;
                        writeln!(out, "{}", swcontrol_msg)?;
                    }
                },
                (Err(e), _) if is_efi_perm_error(&e) => {
                    writeln!(out, "BIOS support for SGX could not be determined due to a permission issue.")?;
                    writeln!(out, "\nWould you like to re-run this program with sudo to try again?\n{}", Paint::red("TODO"))?;
                }
                (&SGX_UNKNOWN, Err(_)) | (Err(_), Err(_)) => {
                    writeln!(out, "BIOS support for SGX could not be determined. Reboot your machine and try to enable SGX in your BIOS. Alternatively, try updating your BIOS to the latest version or contact your BIOS vendor.")?;
                }
            }
        }

        out.verbose();
        if let Some(ref cpuid_err) = inner.cpuid_err {
            let s = cpuid_err.to_string();
            if s.starts_with("CPUID") {
                writeln!(out, "{}", FailTrace(&cpuid_err))?;
            } else {
                writeln!(out, "CPUID error: {}", FailTrace(&cpuid_err))?;
            }
        }
        match &inner.msr_3ah {
            Ok(Msr3ah { sgx: true, locked: true, .. }) => {},
            Ok(Msr3ah { sgx, locked, .. }) => {
                writeln!(out, "MSR 3Ah IA32_FEATURE_CONTROL.LOCK = {}", *locked as u8)?;
                writeln!(out, "MSR 3Ah IA32_FEATURE_CONTROL.SGX_ENABLE = {}", *sgx as u8)?;
            },
            Err(e) => {
                writeln!(out, "Error reading MSR 3Ah: {}", FailTrace(e))?;
                if debug_msr {
                    writeln!(out, "More debugging information might be available by re-running this program with sudo. Would you like to do that?\n{}", Paint::red("(not supported yet)"))?; //TODO
                }
            }
        }
        match &inner.efi_epcbios {
            Ok(var) => writeln!(out, "{:?}", var)?,
            Err(e) => writeln!(out, "Error reading EFI variable EPCBIOS: {}", FailTrace(e))?,
        }
        match &inner.efi_epcsw {
            Ok(var) => writeln!(out, "{:?}", var)?,
            Err(e) => writeln!(out, "Error reading EFI variable EPCSW: {}", FailTrace(e))?,
        }
        match &inner.efi_status {
            Ok(var) => writeln!(out, "{:?}", var)?,
            Err(e) => writeln!(out, "Error reading EFI variable SOFTWAREGUARDSTATUS: {}", FailTrace(e))?,
        }

        out.help_link(help_link)
    }
}

impl DebugSupport for EnclaveAttributes {
    fn debug(&self, mut out: debug::Output, _items: &DetectItemMap) -> fmt::Result {
        writeln!(out, "Your hardware supports SGX, but the supported SGX attributes are misconfigured. This could indicate a CPU or hypervisor bug.")?;
        out.verbose();
        match self.inner {
            Some(EnclaveAttributesInner { cpuid_12h_1: Err(ref e), .. }) => writeln!(out, "CPUID error: {}", FailTrace(e))?,
            Some(EnclaveAttributesInner { cpuid_12h_1: Ok(attr), .. }) => {
                writeln!(out, "Supported attributes: {:?}", attr.attributes_flags_valid)?;
                writeln!(out, "Supported XFRM: {:016x}", attr.attributes_xfrm_valid)?;
            },
            _ => unreachable!(),
        }
        out.help_link("invalid-cpuid")
    }
}

impl DebugSupport for EnclavePageCache {
    fn debug(&self, mut out: debug::Output, _items: &DetectItemMap) -> fmt::Result {
        let inner = self.inner.as_ref().unwrap();
        if !inner.any_unknown && inner.cpuid_12h_epc.is_ok() {
            writeln!(out, "Your hardware supports SGX, but no Enclave Page Cache (EPC) is configured. This could indicate a BIOS or hypervisor bug.")?;
        } else {
            writeln!(out, "Your hardware supports SGX, but the Enclave Page Cache (EPC) is misconfigured. This could indicate a CPU or hypervisor bug.")?;
        }

        out.verbose();
        match &inner.cpuid_12h_epc {
            Err(e) => writeln!(out, "CPUID error: {}", FailTrace(e))?,
            Ok(sections) => {
                for (i, section) in sections.iter().enumerate() {
                    match section {
                        Cpuid12hEnum::Epc { ty: EpcType::ConfidentialityIntegrityProtected, .. } => {},
                        Cpuid12hEnum::Epc { ty, .. } => writeln!(out, "CPUID.(EAX=12H,ECX={:X}H):ECX[3:0] = {:?}", i + 2, ty)?,
                        sect => writeln!(out, "CPUID.(EAX=12H,ECX={:X}H):EAX[3:0] = {:?}", i + 2, sect)?,
                    }
                }
            },
        }
        out.help_link("invalid-cpuid")
    }
}

impl DebugSupport for FlcCpuConfiguration {
    fn debug(&self, mut out: debug::Output, items: &DetectItemMap) -> fmt::Result {
        // don't print any guidance for FLC unless SGX itself is enabled
        if items.lookup::<Isa>().supported() != Status::Supported {
            return Ok(());
        }

        if let Some(Err(err)) = &self.msr_3ah {
            // don't print any guidance if it appears to work
            if items.lookup::<RunEnclaveProdWrap>().supported() == Status::Supported {
                return Ok(());
            }

            writeln!(out, "Your hardware supports Flexible Launch Control, but whether it's enabled could not be determined. More information might be available by re-running this program with sudo. Would you like to do that?\n{}", Paint::red("(not supported yet)"))?; //TODO

            out.verbose();
            writeln!(out, "Error reading MSR 3Ah: {}", FailTrace(err))?;
        } else {
            writeln!(out, "Your hardware supports Flexible Launch Control, but it's not enabled in the BIOS. Reboot your machine and try to enable FLC in your BIOS. Alternatively, try updating your BIOS to the latest version or contact your BIOS vendor.")?;

            out.verbose();
            writeln!(out, "MSR 3Ah IA32_FEATURE_CONTROL.SGX_LC = 0")?;
        }

        out.help_link("flc-cpu-configuration")
    }
}

impl DebugSupport for DeviceLoader {
    fn debug(&self, mut out: debug::Output, _items: &DetectItemMap) -> fmt::Result {
        fn len_to_mod_str(v: &[String]) -> (&str, &str) {
            match v.len() {
                1 => ("", "is"),
                _ => ("s", "are"),
            }
        }

        let inner = self.inner.as_ref().unwrap();

        let err = inner.devpath.as_ref().unwrap_err();

        if let Some(DetectError::NotAvailableInTest) = err.downcast_ref() {
            return Ok(());
        }

        let mut known_error = false;
        if let Some(ioe) = err.downcast_ref::<io::Error>() {
            if ioe.kind() == io::ErrorKind::NotFound {
                known_error = true;
                writeln!(out, "The SGX device (/dev/sgx or /dev/isgx) is not present.\n")?;

                match inner.modstatus {
                    Ok(KmodStatus { ref loaded, .. }) if !loaded.is_empty() => {
                        let (suffix, verb) = len_to_mod_str(&loaded);
                        writeln!(out, "The following module{} {} loaded: {}. Check your kernel logs to see why the device is not available.", suffix, verb, loaded.join(", "))?;
                    },
                    Ok(KmodStatus { ref available, .. }) if !available.is_empty() => {
                        let (suffix, verb) = len_to_mod_str(&available);
                        writeln!(out, "The following module{} {} available, but not loaded: {}. Would you like to load the module{} now? (N.B. you might want to configure the module to load automatically.)\n{}", suffix, verb, available.join(", "), suffix, Paint::red("(not supported yet)"))?; //TODO
                    },
                    Ok(_) => {
                        writeln!(out, "It appears you don't have the kernel module installed. Would you like to install it now?\n{}", Paint::red("(not supported yet)"))?; //TODO
                    },
                    Err(_) => {
                        writeln!(out, "It could not be detected whether you have an SGX driver installed. Please make sure the SGX driver is installed and loaded correctly.")?;
                    },
                }
            } else if ioe.kind() == io::ErrorKind::PermissionDenied {
                known_error = true;
                writeln!(out, "Permission denied while opening the SGX device (/dev/sgx or /dev/isgx). Make sure you have the necessary permissions to create SGX enclaves. If you are running in a container, make sure the device permissions are correctly set on the container.")?;
            }
        }

        if !known_error {
            writeln!(out, "The SGX device (/dev/sgx or /dev/isgx) could not be opened: {}.", err)?;
        }

        out.verbose();
        writeln!(out, "Error opening device: {}", FailTrace(err))?;
        if let Err(ref e) = inner.modstatus {
            writeln!(out, "Error checking module status: {}", FailTrace(e))?;
        }

        out.help_link("sgx-driver")
    }
}

impl DebugSupport for AesmService {
    fn debug(&self, mut out: debug::Output, items: &DetectItemMap) -> fmt::Result {
        let inner = self.inner.as_ref().unwrap();

        if let Err(ref e) = inner.service {
            if let Some(DetectError::NotAvailableInTest) = e.downcast_ref() {
                return Ok(());
            }
        }

        let reason = if items.lookup::<RunEnclave>().supported() == Status::Supported {
            "AESM is needed for generating EPID attestations."
        } else {
            "AESM is needed for launching enclaves and generating attestations."
        };

        writeln!(out, "AESM could not be contacted. {}\n", reason)?;

        match inner.install_state {
            Some(AesmStatus::Absent) => writeln!(out, "AESM appears to not be installed. Would you like to install it?\n{}", Paint::red("(not supported yet)"))?, //TODO
            Some(AesmStatus::Installed) => writeln!(out, "AESM appears to be installed, but it's not running. Please check your AESM installation.")?,
            Some(AesmStatus::Running) => writeln!(out, "AESM appears to be running. Please file a bug report at https://github.com/fortanix/rust-sgx or contact your Fortanix representative.")?,
            None => writeln!(out, "Please check your AESM installation.")?
        }

        out.verbose();
        writeln!(out, "{}", FailTrace(inner.service.as_ref().unwrap_err()))?;

        out.help_link("aesm-service")
    }
}

impl DebugSupport for RunEnclaveDebug {
    fn debug(&self, mut out: debug::Output, _items: &DetectItemMap) -> fmt::Result {
        writeln!(out, "The enclave could not be launched.")?;

        out.verbose();
        if let Some(Err(ref e)) = self.success {
            writeln!(out, "{}", FailTrace(e))?;
        }

        out.help_link("run-enclave-debug")
    }
}

impl DebugSupport for RunEnclaveProd {
    fn debug(&self, mut out: debug::Output, _items: &DetectItemMap) -> fmt::Result {
        writeln!(out, "The enclave could not be launched. This might indicate a problem with FLC.")?;

        out.verbose();
        if let Some(Err(ref e)) = self.success {
            writeln!(out, "{}", FailTrace(e))?;
        }

        out.help_link("run-enclave-prod")
    }
}

impl DebugSupport for RunEnclaveProdWl {
    fn debug(&self, mut out: debug::Output, _items: &DetectItemMap) -> fmt::Result {
        writeln!(out, "The enclave could not be launched. This might indicate a problem with AESM or your internet connection.")?;

        out.verbose();
        if let Some(Err(ref e)) = self.success {
            writeln!(out, "{}", FailTrace(e))?;
        }

        out.help_link("run-enclave-prodwl")
    }
}

#[derive(Copy, Clone)]
enum DebugState {
    Off,
    DebugStart,
    LineStart,
    InLine,
    Hidden,
}

pub struct Output {
    name: Vec<&'static str>,
    verbose: bool,
    started_output: bool,
    debug_state: DebugState,
}

impl Output {
    pub fn new(path: Vec<&'static str>, verbose: bool) -> Self {
        Output {
            name: path,
            verbose,
            started_output: false,
            debug_state: DebugState::Off,
        }
    }

    pub fn verbose(&mut self) {
        if let DebugState::Off = self.debug_state {
            self.debug_state = DebugState::DebugStart
        }
    }

    pub fn help_link(mut self, name: &str) -> fmt::Result {
        self.debug_state = DebugState::Off;
        writeln!(self, "\nMore information: https://edp.fortanix.com/docs/installation/help/#{}", name)
    }
}

impl fmt::Write for Output {
    fn write_str(&mut self, mut s: &str) -> fmt::Result {
        let fmt = |_| fmt::Error;
        
        let stdout = stdout();
        let mut stdout = stdout.lock();
        if !self.started_output {
            self.started_output = true;
            let path = self.name.join(" > ");
            writeln!(stdout, "\n{}{}", paintalt("🕮  ", "help: ").fg(Color::Blue), Paint::new(path).bold()).map_err(fmt)?;
        }

        while !s.is_empty() {
            if let DebugState::DebugStart = self.debug_state {
                writeln!(stdout, "").map_err(fmt)?;
                self.debug_state = DebugState::LineStart;
            }

            if let DebugState::LineStart = self.debug_state {
                self.debug_state = if !self.verbose {
                    writeln!(stdout, "{}", Paint::white("(run with `--verbose` for more details)")).map_err(fmt)?;
                    DebugState::Hidden
                } else {
                    write!(stdout, "{}", Paint::white("debug: ")).map_err(fmt)?;
                    DebugState::InLine
                };
            }

            match self.debug_state {
                DebugState::Off => {
                    stdout.write_all(s.as_bytes()).map_err(fmt)?;
                    s = "";
                },
                DebugState::InLine => {
                    if let Some(linepos) = s.find('\n') {
                        let linepos = linepos + 1;
                        stdout.write_all(s[..linepos].as_bytes()).map_err(fmt)?;
                        s = &s[linepos..];
                        self.debug_state = DebugState::LineStart;
                    } else {
                        stdout.write_all(s.as_bytes()).map_err(fmt)?;
                        s = "";
                    }
                },
                DebugState::Hidden => break,
                // handled above
                _ => unreachable!()
            }
        }

        return Ok(())
    }
}
