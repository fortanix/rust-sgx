/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::ops::RangeInclusive;
use std::convert::TryFrom;

use crate::{Command, Library};
use crate::stream_router::{StreamRouter};


pub trait EnclavePlatform<T: EnclaveType> {
    type Loader;

    fn build(self, loader: Self::Loader, configuration: EnclaveConfiguration, type_configuration: T::Configuration) -> Result<T, anyhow::Error>;
}

pub struct EnclaveConfiguration {
    pub stream_router: Box<dyn StreamRouter + Send + Sync>,
    pub forward_panics: bool,
}

pub trait EnclaveTypePrivate {
    type ConfigurationBuilder: Default;
}

pub trait EnclaveType: EnclaveTypePrivate {
    type Configuration: TryFrom<Self::ConfigurationBuilder, Error = anyhow::Error>;
}

impl EnclaveType for Command {
    type Configuration = CommandConfiguration;
}

impl EnclaveTypePrivate for Command {
    type ConfigurationBuilder = CommandConfigurationBuilder;
}

#[non_exhaustive]
pub struct CommandConfiguration {
    pub cmd_args: Vec<Vec<u8>>,
    pub num_worker_threads: usize,
}

pub struct CommandConfigurationBuilder {
    pub(crate) cmd_args: Vec<Vec<u8>>,
    pub(crate) num_worker_threads: Option<usize>,
}

impl Default for CommandConfigurationBuilder {
    fn default() -> Self {
        CommandConfigurationBuilder {
            cmd_args: vec![b"enclave".to_vec()],
            num_worker_threads: None,
        }
    }
}

impl TryFrom<CommandConfigurationBuilder> for CommandConfiguration {
    type Error = anyhow::Error;
    
    fn try_from(builder: CommandConfigurationBuilder) -> Result<Self, Self::Error> {
        if let Some(num_worker_threads) = builder.num_worker_threads {
            const NUM_WORKER_THREADS_RANGE: RangeInclusive<usize> = 1..=65536;
            anyhow::ensure!(
                NUM_WORKER_THREADS_RANGE.contains(&num_worker_threads),
                "`num_worker_threads` must be in range {NUM_WORKER_THREADS_RANGE:?}"
            );
        }
        let num_worker_threads = builder.num_worker_threads.unwrap_or_else(num_cpus::get);

        Ok(CommandConfiguration {
            cmd_args: builder.cmd_args,
            num_worker_threads,
        })
    }
}



impl EnclaveType for Library {
    type Configuration = LibraryConfiguration;
}

impl EnclaveTypePrivate for Library {
    type ConfigurationBuilder = LibraryConfigurationBuilder;
}

#[non_exhaustive]
pub struct LibraryConfiguration {
}

#[derive(Default)]
pub struct LibraryConfigurationBuilder {
}

impl TryFrom<LibraryConfigurationBuilder> for LibraryConfiguration {
    type Error = anyhow::Error;
    
    fn try_from(_: LibraryConfigurationBuilder) -> Result<Self, Self::Error> {
        Ok(LibraryConfiguration {})
    }
}
