/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::convert::TryInto;
use std::path::{Path, PathBuf};

use clap::clap_app;
use pcs::PckID;
use rustc_serialize::hex::ToHex;
use serde::de::{value, IntoDeserializer};
use serde::Deserialize;

use crate::{
    AzureProvisioningClientBuilder, Error, IntelProvisioningClientBuilder, PcsVersion,
    ProvisioningClient, StatusCode,
};

#[derive(Debug, Deserialize, Copy, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "kebab-case")]
enum Origin {
    Intel,
    Azure,
}

fn str_deserialize(s: &str) -> value::StrDeserializer<value::Error> {
    s.into_deserializer()
}

fn parse_origin(p: &str) -> Result<Origin, String> {
    Origin::deserialize(str_deserialize(p)).map_err(|e| e.to_string())
}

fn download_dcap_artifacts(
    prov_client: &dyn ProvisioningClient,
    pckid_file: &str,
    output_dir: &str,
    verbose: bool,
) -> Result<(), Error> {
    for (idx, pckid) in PckID::parse_file(&PathBuf::from(&pckid_file).as_path())?
        .iter()
        .enumerate()
    {
        let enc_ppid = &pckid.enc_ppid.as_slice();
        if verbose {
            println!("==[ entry {} ]==", idx);
            println!(" Info:");
            println!(
                "   Encr. PPID:  {}..{}",
                enc_ppid[..12].to_hex(),
                enc_ppid[enc_ppid.len() - 3..].to_hex()
            );
            println!("   pce_id:      {}", &&pckid.pce_id.to_le_bytes().to_hex());
            println!("   cpu svn:     {}", pckid.cpu_svn.as_slice().to_hex());
            println!(
                "   pce isvsvn:  {}",
                pckid.pce_isvsvn.to_le_bytes().to_hex()
            );
            println!("   qe_id:       {}", pckid.qe_id.as_slice().to_hex());
            println!(" Storing artifacts:");
        }

        // Fetch pckcerts, note that Azure does not support this API, instead we mimic it
        let pckcerts = match prov_client.pckcerts(&pckid.enc_ppid, pckid.pce_id) {
            Ok(pckcerts) => pckcerts,
            Err(Error::RequestNotSupported) => prov_client
                .pckcert(
                    None,
                    &pckid.pce_id,
                    &pckid.cpu_svn,
                    pckid.pce_isvsvn,
                    Some(&pckid.qe_id),
                )?
                .try_into()
                .map_err(|e| Error::PCSDecodeError(format!("{}", e).into()))?,
            Err(e) => return Err(e),
        };
        let pckcerts_file = pckcerts.store(output_dir, pckid.qe_id.as_slice())?;

        if verbose {
            println!("   pckcerts:    {}", pckcerts_file);
        }

        let fmspc = pckcerts.fmspc()?;
        let tcbinfo = prov_client.tcbinfo(&fmspc)?;
        let tcbinfo_file = tcbinfo
            .store(output_dir)
            .map_err(|e| Error::OfflineAttestationError(e))?;

        if verbose {
            println!("   tcb info:    {}\n", tcbinfo_file);
        }
    }
    let pckcrl = prov_client
        .pckcrl()
        .and_then(|crl| crl.write_to_file(output_dir).map_err(|e| e.into()))?;
    let qe_identity = prov_client
        .qe_identity()
        .and_then(|qe_id| qe_id.write_to_file(output_dir).map_err(|e| e.into()))?;
    if verbose {
        println!("==[ generic ]==");
        println!("   pckcrl:      {}", pckcrl);
        println!("   QE identity: {}", qe_identity);
    }
    Ok(())
}

pub fn main() {
    fn is_directory(directory_path: String) -> Result<(), String> {
        let path = Path::new(&directory_path);

        match (path.exists(), path.is_dir()) {
            (true, true) => return Ok(()),
            (true, false) => {
                return Err(format!(
                    "Path {} exists, but is not a directory",
                    directory_path
                ))
            }
            (false, _) => return Err(format!("Directory {} does not exists", directory_path)),
        };
    }

    fn is_file(filename: String) -> Result<(), String> {
        if Path::new(&filename).exists() {
            Ok(())
        } else {
            Err(format!("Cannot open {}", filename))
        }
    }

    fn parse_pcs_version(value: &str) -> Result<PcsVersion, String> {
        match value {
            "3" => Ok(PcsVersion::V3),
            "4" => Ok(PcsVersion::V4),
            _ => Err(format!(
                "Expected 3 or 4, found `{}`",
                value
            )),
        }
    }

    let matches = clap::clap_app!(("DCAP Artifact Retrieval Tool") =>
        (author: "Fortanix")
        (about: "Fortanix ecdsa artifact retrieval tool for DCAP attestation")
            (
                @arg ORIGIN: --("origin") +takes_value
                validator(|s| parse_origin(s.as_str()).map(|_| ()))
                "Location from where artifacts need to be fetched. Options are: \"intel\" and \"azure\".\
                 Note that Azure does not provide access to all artifacts. Intel will be contacted as a fallback (default: \"intel\")"
            )
            (
                @arg PCKID_FILE: --("pckid-file") +takes_value +required requires("PCKID_FILE")
                validator(is_file)
                "File describing the PCK identity (outputted by PCKIDRetrievalTool)"
            )
            (
                @arg OUTPUT_DIR: --("output-dir") +takes_value +required requires("OUTPUT_DIR")
                validator(is_directory)
                "Destination folder for data retrieved from Intel certification services"
            )
            (
                @arg API_VERSION: --("api-version") +takes_value
                validator(|s| parse_pcs_version(s.as_str()).map(|_| ()))
                "API version for provisioning service, supported values are 3 and 4 (default: 3)"
            )
            (
                @arg API_KEY: --("api-key") +takes_value
                "API key for authenticating with Intel provisioning service"
            )
            (
                @arg VERBOSE: -v --verbose
                "Print information of which files are fetched"
            )
        )
        .get_matches();

    let result = match (
        matches.value_of("PCKID_FILE"),
        matches.value_of("OUTPUT_DIR"),
    ) {
        (Some(pckid_file), Some(output_dir)) => {
            let verboseness = matches.occurrences_of("VERBOSE");
            let api_version = parse_pcs_version(matches.value_of("API_VERSION").unwrap_or("3"))
                .expect("validated");

            let origin =
                parse_origin(matches.value_of("ORIGIN").unwrap_or("intel")).expect("validated");

            let fetcher = crate::reqwest_client();
            let client: Box<dyn ProvisioningClient> = match origin {
                Origin::Intel => {
                    let mut client_builder = IntelProvisioningClientBuilder::new(api_version);
                    if let Some(api_key) = matches.value_of("API_KEY") {
                        client_builder.set_api_key(api_key.into());
                    }
                    Box::new(client_builder.build(fetcher))
                }
                Origin::Azure => {
                    let client_builder = AzureProvisioningClientBuilder::new(api_version);
                    Box::new(client_builder.build(fetcher))
                }
            };
            download_dcap_artifacts(&*client, pckid_file, output_dir, 0 < verboseness)
        }
        _ => unreachable!("validated"),
    };

    match result {
        Ok(()) => {}
        Err(Error::PCSError(StatusCode::NotFound, _)) => {
            eprintln!("Error: Artifact not found. Perhaps specify a different origin?");
            std::process::exit(1);
        }
        Err(err) => {
            eprintln!("Error downloading artifact: {}", err);
            std::process::exit(1);
        }
    }
}
