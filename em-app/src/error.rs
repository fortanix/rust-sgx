/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */
use std::{error, fmt};

type RemoteError = Box<dyn error::Error + 'static>;

#[derive(Debug)]
pub enum Error {
    // Errors returned by ExternalKey trait functions.
    ExternalKey(RemoteError),

    // Errors returned by ExternalKey trait functions.
    ExternalKeyString(String),

    // Errors establishing connection to node agent.
    NodeAgentClient(RemoteError),

    // Errors returned by remote calls when fetching target-info
    TargetReport(RemoteError),

    // Error creating a hash over target report.
    TargetReportHash(RemoteError),

    // Internal errors specific to parsing remote data or code issues when fetching target-info
    TargetReportInternal(String),

    // Errors when fetching attestation certificate.
    AttestationCert(RemoteError),

    // Errors when hashing data during attestation certificate processing.
    AttestationCertHash(RemoteError),

    // Internal errors specific to parsing remote data or code issues when fetching attestation certificates
    AttestationCertInternal(String),

    // Validation failed for data returned by Node Agent. (possibly tampered or protocol issues)
    AttestationCertValidation(String),

    // Error replies from Node Agent for certificate issue
    CertIssue(RemoteError),

    // Error using provided application config id.
    ConfigIdIssue(String),

    // Error generating nonce
    NonceGeneration(RemoteError),

    // Errors for nitro when accessing driver
    NsmDriver(String),

    // Unexpected response from NSM driver
    UnexpectedNsmResponse(String),
}

impl std::error::Error for crate::Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Error::ExternalKey(e) |
            Error::NodeAgentClient(e) |
            Error::TargetReport(e) |
            Error::TargetReportHash(e) |
            Error::AttestationCert(e) |
            Error::AttestationCertHash(e) |
            Error::CertIssue(e) |
            Error::NonceGeneration(e) => Some(e.as_ref()),
            Error::ExternalKeyString(_) |
            Error::TargetReportInternal(_) |
            Error::AttestationCertInternal(_) |
            Error::AttestationCertValidation(_) |
            Error::ConfigIdIssue(_) |
            Error::NsmDriver(_) |
            Error::UnexpectedNsmResponse(_) => None,
        }
    }
}

impl fmt::Display for crate::Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &*self {
            Error::ExternalKey(e)               => write!(f, "External key returned error: {}", e),
            Error::ExternalKeyString(e)         => write!(f, "External key returned error: {}", e),
            Error::NodeAgentClient(e)           => write!(f, "Error creating node agent client: {}", e),
            Error::TargetReport(e)              => write!(f, "Unable to get target report from node agent: {}", e),
            Error::TargetReportHash(e)          => write!(f, "Failure in hash operations while processing target report: {}", e),
            Error::TargetReportInternal(e)      => write!(f, "Internal error in target report handling: {}", e),
            Error::AttestationCert(e)           => write!(f, "Failure requesting attestation certificate: {}", e),
            Error::AttestationCertHash(e)       => write!(f, "Failure in hash operations while processing attestation certificate: {}", e),
            Error::AttestationCertInternal(e)   => write!(f, "Internal error in processing attestation certificate: {}", e),
            Error::AttestationCertValidation(e) => write!(f, "Validation failed for data returned by Node Agent: {}", e),
            Error::CertIssue(e)                 => write!(f, "Failure in final certificate issue step: {}", e),
            Error::ConfigIdIssue(e)             => write!(f, "Failure in parsing input application config id: {}", e),
            Error::NonceGeneration(e)           => write!(f, "Failure generating nonce: {}", e),
            Error::NsmDriver(e)                 => write!(f, "Failure in communicating with NSM driver: {}", e),
            Error::UnexpectedNsmResponse(e)     => write!(f, "Unexpected response from NSM driver: {}", e),
        }
    }
}
