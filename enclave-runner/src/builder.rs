/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::convert::TryInto;

use crate::Command;
use crate::platform::*;
use crate::stream_router::{StreamRouter, OsStreamRouter};

pub struct EnclaveBuilder<P: EnclavePlatform<T>, T: EnclaveType> {
    platform: P,
    stream_router: Option<Box<dyn StreamRouter + Send + Sync>>,
    forward_panics: bool,
    type_builder: T::ConfigurationBuilder,
}

impl<P: EnclavePlatform<T>, T: EnclaveType> EnclaveBuilder<P, T> {
    pub fn new(platform: P) -> Self {
        EnclaveBuilder {
            platform,
            stream_router: None,
            forward_panics: false,
            type_builder: Default::default(),
        }
    }

    /// The stream router that this enclave should use when the enclave is
    /// creating any streams. Defaults to [`OsStreamRouter`].
    pub fn stream_router<R: Into<Box<dyn StreamRouter + Send + Sync>>>(&mut self, router: R) -> &mut Self {
        self.stream_router = Some(router.into());
        self
    }

    /// Whether to panic the runner if any enclave thread panics.
    /// Defaults to `false`.
    /// Note: If multiple enclaves are loaded, and an enclave with this set to
    /// true panics, then all enclaves handled by this runner will exit because
    /// the runner itself will panic.
    pub fn forward_panics(&mut self, fp: bool) -> &mut Self {
        self.forward_panics = fp;
        self
    }

    pub fn build(self, loader: P::Loader) -> Result<T, anyhow::Error> {
        let configuration = EnclaveConfiguration {
            stream_router: self.stream_router.unwrap_or_else(|| OsStreamRouter::new()),
            forward_panics: self.forward_panics,
        };
        self.platform.build(loader, configuration, self.type_builder.try_into()?)
    }
}

impl<P: EnclavePlatform<Command>> EnclaveBuilder<P, Command> where {
    /// Adds multiple arguments to pass to enclave's `fn main`.
    /// **NOTE:** This is not an appropriate channel for passing secrets or
    /// security configurations to the enclave.
    pub fn args<I, S>(&mut self, args: I) -> &mut Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<[u8]>,
    {
        let args = args.into_iter().map(|a| a.as_ref().to_owned());
        self.type_builder.cmd_args.extend(args);
        self
    }

    /// Adds an argument to pass to enclave's `fn main`.
    /// **NOTE:** This is not an appropriate channel for passing secrets or
    /// security configurations to the enclave.
    pub fn arg<S: AsRef<[u8]>>(&mut self, arg: S) -> &mut Self {
        let arg = arg.as_ref().to_owned();
        self.type_builder.cmd_args.push(arg);
        self
    }

    /// Sets the number of worker threads used to run the enclave.
    pub fn num_worker_threads(&mut self, num_worker_threads: usize) -> &mut Self {
        self.type_builder.num_worker_threads = Some(num_worker_threads);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    struct TestEnclaveBuilder(Vec<String>);

    impl EnclavePlatform<Command> for TestEnclaveBuilder {
        type Loader = ();

        fn build(
            self,
            _loader: Self::Loader,
            _configuration: EnclaveConfiguration,
            cmd_configuration: CommandConfiguration,
        ) -> Result<Command, anyhow::Error> {
            let f = Box::new(move || {
                let enclave_args = cmd_configuration
                    .cmd_args
                    .into_iter()
                    .map(|arr| String::from_utf8(arr))
                    .collect::<Result<Vec<_>, _>>()?;
                assert_eq!(
                    self.0, enclave_args,
                    "{:?} differs from expected: {:?}",
                    enclave_args, self.0
                );
                Ok(())
            }) as Box<dyn FnOnce() -> _>;
            Ok(f.into())
        }
    }

    #[test_case(vec![]; "empty")]
    #[test_case(vec!["--arg1".to_owned(), "--arg2".to_owned()]; "with args")]
    fn test_enclave_args(args: Vec<String>) {
        let mut expected = vec!["enclave".to_owned()];
        expected.extend_from_slice(&args[..]);
        let enclave_builder = TestEnclaveBuilder(expected);
        let mut enclave_builder = EnclaveBuilder::new(enclave_builder);
        enclave_builder.args(args);
        enclave_builder.build(()).unwrap().run().unwrap();
    }
}
