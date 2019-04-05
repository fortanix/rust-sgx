/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io::Error as IoError;
use std::result::Result as StdResult;

pub type Result<T> = StdResult<T, Error>;

// These numbers are from psw/ae/inc/internal/aesm_error.h and (surprisingly)
// not from psw/ae/inc/aeerror.h
#[derive(Debug, Copy, Clone)]
#[allow(non_camel_case_types)]
pub enum AesmError {
    UnexpectedError_1,
    NoDeviceError_2,
    ParameterError_3,
    EpidblobError_4,
    EpidRevokedError_5,
    GetLicensetokenError_6,
    SessionInvalid_7,
    MaxNumSessionReached_8,
    PsdaUnavailable_9,
    EphSessionFailed_10,
    LongTermPairingFailed_11,
    NetworkError_12,
    NetworkBusyError_13,
    ProxySettingAssist_14,
    FileAccessError_15,
    SgxProvisionFailed_16,
    ServiceStopped_17,
    Busy_18,
    BackendServerBusy_19,
    UpdateAvailable_20,
    OutOfMemoryError_21,
    MsgError_22,
    ThreadError_23,
    SgxDeviceNotAvailable_24,
    EnableSgxDeviceFailed_25,
    PlatformInfoBlobInvalidSig_26,
    ServiceNotAvailable_27,
    KdfMismatch_28,
    OutOfEpc_29,
    ServiceUnavailable_30,
    UnrecognizedPlatform_31,
    EcdsaIdMismatch_32,
    PathnameBufferOverflow_33,
    ErrorStoredKey_34,
    PubKeyIdMismatch_35,
    InvalidPceSigScheme_36,
    AttKeyBlobError_37,
    UnsupportedAttKeyId_38,
    UnsupportedLoadingPolicy_39,
    InterfaceUnavailable_40,
    PlatformLibUnavailable_41,
    AttKeyNotInitialized_42,
    AttKeyCertDataInvalid_43,
    NoPlatformCertData_44,
    ReportError_45,
    EnclaveLost_46,
    InvalidReport_47,
    EnclaveLoadError_48,
    UnableToGenerateQeReport_49,
    KeyCertificationError_50,
    Unknown(u32),
}

impl From<u32> for AesmError {
    fn from(n: u32) -> AesmError {
        use self::AesmError::*;
        match n {
            1 => UnexpectedError_1,
            2 => NoDeviceError_2,
            3 => ParameterError_3,
            4 => EpidblobError_4,
            5 => EpidRevokedError_5,
            6 => GetLicensetokenError_6,
            7 => SessionInvalid_7,
            8 => MaxNumSessionReached_8,
            9 => PsdaUnavailable_9,
            10 => EphSessionFailed_10,
            11 => LongTermPairingFailed_11,
            12 => NetworkError_12,
            13 => NetworkBusyError_13,
            14 => ProxySettingAssist_14,
            15 => FileAccessError_15,
            16 => SgxProvisionFailed_16,
            17 => ServiceStopped_17,
            18 => Busy_18,
            19 => BackendServerBusy_19,
            20 => UpdateAvailable_20,
            21 => OutOfMemoryError_21,
            22 => MsgError_22,
            23 => ThreadError_23,
            24 => SgxDeviceNotAvailable_24,
            25 => EnableSgxDeviceFailed_25,
            26 => PlatformInfoBlobInvalidSig_26,
            27 => ServiceNotAvailable_27,
            28 => KdfMismatch_28,
            29 => OutOfEpc_29,
            30 => ServiceUnavailable_30,
            31 => UnrecognizedPlatform_31,
            32 => EcdsaIdMismatch_32,
            33 => PathnameBufferOverflow_33,
            34 => ErrorStoredKey_34,
            35 => PubKeyIdMismatch_35,
            36 => InvalidPceSigScheme_36,
            37 => AttKeyBlobError_37,
            38 => UnsupportedAttKeyId_38,
            39 => UnsupportedLoadingPolicy_39,
            40 => InterfaceUnavailable_40,
            41 => PlatformLibUnavailable_41,
            42 => AttKeyNotInitialized_42,
            43 => AttKeyCertDataInvalid_43,
            44 => NoPlatformCertData_44,
            45 => ReportError_45,
            46 => EnclaveLost_46,
            47 => InvalidReport_47,
            48 => EnclaveLoadError_48,
            49 => UnableToGenerateQeReport_49,
            50 => KeyCertificationError_50,
            _ => Unknown(n),
        }
    }
}

#[derive(Fail, Debug)]
pub enum Error {
    #[fail(display = "aesm error code {:?}", _0)]
    AesmCode(AesmError),
    #[fail(display = "error communicating with aesm")]
    AesmCommunication(#[cause] IoError),
    #[fail(display = "missing expected {} payload in response from aesm", _0)]
    AesmBadResponse(String),
    #[fail(display = "invalid quote type {}", _0)]
    InvalidQuoteType(u32),
    #[fail(display = "invalid quote size")]
    InvalidQuoteSize,
    #[fail(display = "invalid token size")]
    InvalidTokenSize,
}

impl From<IoError> for Error {
    fn from(err: IoError) -> Error {
        Error::AesmCommunication(err)
    }
}

impl Error {
    pub fn aesm_code(code: u32) -> Error {
        Error::AesmCode(code.into())
    }

    pub fn aesm_bad_response(expected: &str) -> Error {
        Error::AesmBadResponse(expected.to_owned())
    }
}
