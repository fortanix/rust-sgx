/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use crate::{Command, Library};
use crate::stream_router::StreamRouter;

pub trait EnclavePlatform<T: EnclaveType> {
    type Loader;

    fn build(self, loader: Self::Loader, configuration: EnclaveConfiguration, type_configuration: T::Configuration) -> Result<T, anyhow::Error>;
}

pub struct EnclaveConfiguration {
    pub stream_router: Box<dyn StreamRouter + Send + Sync>,
    pub forward_panics: bool,
}

pub trait EnclaveTypePrivate {}

pub trait EnclaveType: EnclaveTypePrivate {
    type Configuration;
}

impl EnclaveType for Command {
    type Configuration = CommandConfiguration;
}

impl EnclaveTypePrivate for Command {}

#[non_exhaustive]
pub struct CommandConfiguration {
    pub cmd_args: Vec<Vec<u8>>,
    pub num_worker_threads: usize,
}

impl EnclaveType for Library {
    type Configuration = LibraryConfiguration;
}

impl EnclaveTypePrivate for Library {}

#[non_exhaustive]
#[derive(Default)]
pub struct LibraryConfiguration {}
