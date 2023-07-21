/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::fmt::Debug;
use std::sync::Arc;

use failure::{Fail, ResultExt};

use sgx_isa::{Attributes, Einittoken, Miscselect, PageType, Sigstruct};
use sgxs::einittoken::EinittokenProvider;
use sgxs::loader;
use sgxs::sgxs::{
    CreateInfo, Error as SgxsError, MeasEAdd, MeasECreate, PageChunks, PageReader, SgxsRead,
};

use crate::isgx::debugging;
use crate::{MappingInfo, Tcs};

pub(crate) trait EnclaveLoad: Debug + Sized + Send + Sync + 'static {
    type Error: Fail + EinittokenError;
    type MapData: Debug + Send + Sync;
    fn new(
        device: Arc<Self>,
        ecreate: MeasECreate,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> Result<Mapping<Self>, Self::Error>;
    fn add(
        mapping: &mut Mapping<Self>,
        page: (MeasEAdd, PageChunks, [u8; 4096]),
    ) -> Result<(), Self::Error>;
    fn init(
        mapping: &mut Mapping<Self>,
        sigstruct: &Sigstruct,
        einittoken: Option<&Einittoken>,
    ) -> Result<(), Self::Error>;
    fn destroy(mapping: &mut Mapping<Self>);
}

pub(crate) trait EinittokenError {
    fn is_einittoken_error(&self) -> bool;
}

#[derive(Debug)]
pub(crate) struct Mapping<D: EnclaveLoad> {
    pub device: Arc<D>,
    pub mapdata: D::MapData,
    pub tcss: Vec<u64>,
    pub base: u64,
    pub size: u64,
}

impl<D: EnclaveLoad> Drop for Mapping<D> {
    fn drop(&mut self) {
        debugging::unregister_terminated_enclave(self.base);
        D::destroy(self)
    }
}

#[derive(Debug)]
pub(crate) struct Device<D> {
    pub inner: Arc<D>,
    pub einittoken_provider: Option<Box<dyn EinittokenProvider>>,
}

pub(crate) struct LoadResult {
    pub info: MappingInfo,
    pub tcss: Vec<Tcs>,
}

impl<T: loader::Load<MappingInfo = MappingInfo, Tcs = Tcs> + ?Sized> Into<loader::Mapping<T>>
    for LoadResult
{
    fn into(self) -> loader::Mapping<T> {
        let LoadResult { info, tcss } = self;
        loader::Mapping { info, tcss }
    }
}

impl<D: EnclaveLoad> Device<D> {
    pub fn load(
        &mut self,
        mut reader: &mut dyn SgxsRead,
        sigstruct: &Sigstruct,
        attributes: Attributes,
        miscselect: Miscselect,
    ) -> ::std::result::Result<LoadResult, ::failure::Error> {
        let mut tokprov = self.einittoken_provider.as_mut();
        let mut tokprov_err = None;
        let einittoken = if let Some(ref mut p) = tokprov {
            match p.token(sigstruct, attributes, false) {
                Ok(token) => Some(token),
                Err(err) => {
                    tokprov_err = Some(err);
                    None
                }
            }
        } else {
            None
        };

        let (CreateInfo { ecreate, sized }, mut reader) = PageReader::new(&mut reader)?;

        if !sized {
            return Err(SgxsError::StreamUnsized.into());
        }

        let mut mapping = D::new(self.inner.clone(), ecreate, attributes, miscselect)?;

        loop {
            match reader.read_page()? {
                Some(page) => {
                    let tcs = if page.0.secinfo.flags.page_type() == PageType::Tcs as u8 {
                        Some(mapping.base + page.0.offset)
                    } else {
                        None
                    };

                    D::add(&mut mapping, page)?;

                    if let Some(tcs) = tcs {
                        mapping.tcss.push(tcs);
                    }
                }
                None => break,
            }
        }

        match (
            D::init(&mut mapping, sigstruct, einittoken.as_ref()),
            tokprov_err,
        ) {
            (Err(ref e), ref mut tokprov_err @ Some(_)) if e.is_einittoken_error() => {
                return Err(tokprov_err.take().unwrap())
                    .context("The EINITTOKEN provider didn't provide a token")
                    .map_err(Into::into);
            }
            (Err(ref e), _)
                if e.is_einittoken_error() && tokprov.as_ref().map_or(false, |p| p.can_retry()) =>
            {
                let einittoken = tokprov
                    .unwrap()
                    .token(sigstruct, attributes, true)
                    .context("The EINITTOKEN provider didn't provide a token")?;
                D::init(&mut mapping, sigstruct, Some(&einittoken))?
            }
            (v, _) => v?,
        }

        let mapping = Arc::new(mapping);

        Ok(LoadResult {
            tcss: mapping
                .tcss
                .iter()
                .map(|&tcs| Tcs {
                    _mapping: mapping.clone(),
                    address: tcs,
                })
                .collect(),
            info: MappingInfo {
                base: mapping.base,
                size: mapping.size,
                _mapping: mapping,
            },
        })
    }
}

pub(crate) struct DeviceBuilder<D> {
    pub device: Device<D>,
}

impl<D> DeviceBuilder<D> {
    pub fn einittoken_provider(
        &mut self,
        einittoken_provider: Box<dyn EinittokenProvider>,
    ) -> &mut Self {
        self.device.einittoken_provider = Some(einittoken_provider);
        self
    }

    pub fn build(self) -> Device<D> {
        self.device
    }
}
