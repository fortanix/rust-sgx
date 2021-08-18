/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#![doc(html_logo_url = "https://edp.fortanix.com/img/docs/edp-logo.svg",
       html_favicon_url = "https://edp.fortanix.com/favicon.ico",
       html_root_url = "https://edp.fortanix.com/docs/api/")]

extern crate enclave_runner;
extern crate failure;
extern crate sgx_isa;
extern crate sgxs;

use failure::{Error, ResultExt};

use enclave_runner::EnclaveBuilder;
use sgx_isa::{PageType, Report, SecinfoFlags, Targetinfo, Attributes, AttributesFlags, Miscselect};
use sgxs::loader::{EnclaveControl, Load, MappingInfo};
use sgxs::sgxs::{PageChunk, SecinfoTruncated, SgxsWrite};

pub struct ReportBuilder {
    enclave_bytes: Vec<u8>,
    attributes: Option<Attributes>,
    miscselect: Option<Miscselect>,
}

impl ReportBuilder {
    pub fn new(targetinfo: &Targetinfo) -> ReportBuilder {
        let mut report_enclave = include_bytes!("../enclave/report.sgxs").to_vec();
        let mut targetinfo: &[u8] = targetinfo.as_ref();
        let secinfo = SecinfoTruncated {
            flags: SecinfoFlags::R | SecinfoFlags::W | PageType::Reg.into(),
        };
        report_enclave
            .write_page(
                (&mut targetinfo, [PageChunk::Included; 16]),
                0x3000,
                secinfo,
            )
            .unwrap();

        ReportBuilder {
            enclave_bytes: report_enclave,
            attributes: None,
            miscselect: None
        }
    }

    pub fn attributes(mut self, mut attributes: Attributes) -> Self {
        attributes.flags |= AttributesFlags::MODE64BIT;
        self.attributes = Some(attributes);
        self
    }

    pub fn miscselect(mut self, miscselect: Miscselect) -> Self {
        self.miscselect = Some(miscselect);
        self
    }

    pub fn build<C: EnclaveControl + Sized, M: MappingInfo<EnclaveControl=C>, L: Load<MappingInfo=M>>(self, enclave_loader: &mut L) -> Result<Report, Error> {
        let mut builder = EnclaveBuilder::new_from_memory(&self.enclave_bytes);

        if let Some(attributes) = self.attributes {
            builder.attributes(attributes);
        }

        if let Some(miscselect) = self.miscselect {
            builder.miscselect(miscselect);
        }

        unsafe {
            let mut report = Report::default();

            builder
                .build_library(enclave_loader)
                .context("failed to load report enclave")?
                .call(&mut report as *mut _ as _, 0, 0, 0, 0)
                .context("failed to call report enclave")?;
            Ok(report)
        }
    }
}

pub fn report<C: EnclaveControl + Sized, M: MappingInfo<EnclaveControl=C>, L: Load<MappingInfo=M>>(targetinfo: &Targetinfo, enclave_loader: &mut L) -> Result<Report, Error> {
    ReportBuilder::new(targetinfo).build(enclave_loader)
}
