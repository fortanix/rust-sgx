use crate::VmeError;
use nitro_cli::enclave_proc_comm;
use nitro_cli::common::{self as nitro_common, logger};
use nitro_cli::common::commands_parser::RunEnclavesArgs;
use nitro_cli::common::json_output::EnclaveRunInfo;
use super::Platform;

pub struct NitroEnclaves;
pub struct RunningNitroEnclave(EnclaveRunInfo);

impl Platform for NitroEnclaves {
    type RunArgs = RunEnclavesArgs;
    type EnclaveDescriptor = RunningNitroEnclave;

    fn run<I: Into<Self::RunArgs>>(run_args: I) -> Result<Self::EnclaveDescriptor, VmeError> {
        let mut run_args: RunEnclavesArgs = run_args.into();
        let logger = logger::init_logger()
            .expect("Log init failed");
        let mut comm = enclave_proc_comm::enclave_proc_spawn(&logger).unwrap();

        let names = nitro_cli::get_all_enclave_names().unwrap();
        if run_args.enclave_name.is_none() {
            run_args.enclave_name = Some(nitro_cli::new_enclave_name(run_args.clone(), names).unwrap());
        }

        nitro_common::enclave_proc_command_send_single(
                nitro_common::EnclaveProcessCommandType::Run,
                Some(&run_args),
                &mut comm,
            ).unwrap();

        // Returns a Vec of `(obj: EnclaveRunInfo, status_code)` for every item in `[comm]`. We need to
        // use this because `enclave_proc_handle_output` is private.
        let mut outs = nitro_cli::enclave_proc_comm::enclave_proc_handle_outputs::<EnclaveRunInfo>(&mut [comm]);

        if outs.len() != 1 {
            /*
            Err(new_nitro_cli_failure!(
                    &format!("Received unexpected number of run infos: {}", outs.len()),
                    NitroCliErrorEnum::UnspecifiedError
                ))
            */
            panic!("Unexpected nitro platform error");
        } else {
            if let Some((out, _statuscode)) = outs.pop() {
                Ok(RunningNitroEnclave(out))
            } else {
                /*
                Err(new_nitro_cli_failure!(
                       &format!("Received unexpected number of run infos: {}", outs.len()),
                        NitroCliErrorEnum::UnspecifiedError
                ))
                */
                panic!("Unexpected nitro platform error");
            }
        }
    }
}

    fn terminate(_enclave: &Self::EnclaveDescriptor) -> Result<(), VmeError> {
        todo!();
    }
}
