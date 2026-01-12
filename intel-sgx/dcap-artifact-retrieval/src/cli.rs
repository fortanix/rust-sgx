/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

use std::path::{Path, PathBuf};

use clap::clap_app;
use pcs::{PckID, DcapArtifactIssuer, WriteOptionsBuilder};
use reqwest::Url;
use rustc_serialize::hex::ToHex;
use serde::de::{value, IntoDeserializer};
use serde::Deserialize;

use crate::{
    AzureProvisioningClientBuilder, Error, IntelProvisioningClientBuilder,
    PccsProvisioningClientBuilder, PcsVersion, ProvisioningClient, StatusCode,
};

// NOTE: unfortunately these default values need to be repeated in arg
// descriptions in `main`. Please keep them in sync.
const DEFAULT_ORIGIN: &'static str = "intel";
const DEFAULT_API_VERSION: &'static str = "4";

#[derive(Debug, Deserialize, Copy, Clone, Eq, PartialEq, Hash)]
#[serde(rename_all = "kebab-case")]
enum Origin {
    Intel,
    Azure,
    Pccs,
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
                "   Encr. PPID:  {}",
                enc_ppid.to_hex(),
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

        // Fetch pckcerts, note that Azure and PCCS do not support this API,
        // instead we mimic it using pckcert API.
        let pckcerts = prov_client.pckcerts_with_fallback(&pckid)?;

        let pckcerts_file = pckcerts.store(output_dir, pckid.qe_id.as_slice(), WriteOptionsBuilder::new().build())?;

        if verbose {
            println!("   pckcerts:    {}", pckcerts_file.unwrap().display());
        }

        let fmspc = pckcerts.fmspc()?;
        let evaluation_data_numbers = prov_client
            .tcb_evaluation_data_numbers()?;

        let file = evaluation_data_numbers.write_to_file(output_dir, WriteOptionsBuilder::new().build())?;
        if verbose {
            println!("   tcb evaluation data numbers:    {}\n", file.unwrap().display());
        }

        for number in evaluation_data_numbers.evaluation_data_numbers()?.numbers() {
            let tcb_info = prov_client
                .tcbinfo(&fmspc, Some(number.number()));

            match tcb_info {
                Ok(tcb_info) => {
                    let file = tcb_info.store(output_dir, WriteOptionsBuilder::new().build())?;
                    if verbose {
                        println!("   tcb info:    {}", file.unwrap().display());
                    }
                },
                Err(Error::PCSError(StatusCode::Gone, _)) => {
                    if verbose {
                        println!("   tcb info:    Gone (silently ignoring)");
                    }
                }
                Err(e) => {
                    return Err(e)?;
                },
            }


            let qe_identity = prov_client
                .qe_identity(Some(number.number()));

            match qe_identity {
                Ok(qe_identity) => {
                    let file = qe_identity.write_to_file(output_dir, WriteOptionsBuilder::new().build())?;
                    if verbose {
                        println!("   qe identity: {}\n", file.unwrap().display());
                    }
                }
                Err(Error::PCSError(StatusCode::Gone, _)) => {
                    if verbose {
                        println!("   qe identity: Gone (silently ignoring)\n");
                    }
                }
                Err(e) => {
                    return Err(e)?;
                },
            }
        }
    }
    let pckcrl = prov_client
        .pckcrl(DcapArtifactIssuer::PCKProcessorCA)
        .and_then(|crl| crl.write_to_file_as(output_dir, DcapArtifactIssuer::PCKProcessorCA, WriteOptionsBuilder::new().build()).map_err(|e| e.into()))?;
    if verbose {
        println!("==[ generic ]==");
        println!("   PCKProcessorCA Crl:      {}", pckcrl.unwrap().display());
    }

    let pckcrl = prov_client
        .pckcrl(DcapArtifactIssuer::PCKPlatformCA)
        .and_then(|crl| crl.write_to_file_as(output_dir, DcapArtifactIssuer::PCKPlatformCA, WriteOptionsBuilder::new().build()).map_err(|e| e.into()))?;
    if verbose {
        println!("   PCKPlatformCA Crl:      {}", pckcrl.unwrap().display());
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
            _ => Err(format!("Expected 3 or 4, found `{}`", value)),
        }
    }

    fn is_url(value: String) -> Result<(), String> {
        let url = Url::parse(&value)
            .map_err(|e| format!("cannot parse `{}` as a valid URL: {}", value, e))?;

        if url.scheme() != "http" && url.scheme() != "https" {
            return Err(format!(
                "Expected an http or https URL found: `{}`",
                url.scheme()
            ));
        }
        Ok(())
    }

    let matches = clap::clap_app!(("DCAP Artifact Retrieval Tool") =>
        (author: "Fortanix")
        (about: "Fortanix ecdsa artifact retrieval tool for DCAP attestation")
            (
                @arg ORIGIN: --("origin") +takes_value
                validator(|s| parse_origin(s.as_str()).map(|_| ()))
                "Origin for downloading artifacts. Options are: \"intel\", \"azure\" and \"pccs\". \
                 Note that Azure does not provide access to all artifacts. Intel will be contacted as a fallback. \
                 Default: \"intel\"."
            )
            (
                @arg PCKID_FILE: --("pckid-file") +takes_value +required requires("PCKID_FILE")
                validator(is_file)
                "File describing the PCK identity (outputted by PCKIDRetrievalTool)."
            )
            (
                @arg OUTPUT_DIR: --("output-dir") +takes_value +required requires("OUTPUT_DIR")
                validator(is_directory)
                "Destination folder for storing downloaded artifacts."
            )
            (
                @arg API_VERSION: --("api-version") +takes_value
                validator(|s| parse_pcs_version(s.as_str()).map(|_| ()))
                "API version for provisioning service, supported values are 3 and 4. Default: \"4\"."
            )
            (
                @arg API_KEY: --("api-key") +takes_value
                "API key for authenticating with Intel provisioning service."
            )
            (
                @arg PCCS_URL: --("pccs-url") +takes_value required_if("ORIGIN", "pccs")
                validator(is_url)
                "PCCS base URL. This is relevant only when using `--origin pccs`."
            )
            (
                @arg INSECURE: -k --insecure
                "Do not verify that server's hostname matches their TLS certificate and accept self-signed certificates. This is insecure."
            )
            (
                @arg VERBOSE: -v --verbose
                "Print additional information abut files that are fetched."
            )
        )
        .get_matches();

    let result = match (
        matches.value_of("PCKID_FILE"),
        matches.value_of("OUTPUT_DIR"),
    ) {
        (Some(pckid_file), Some(output_dir)) => {
            let verboseness = matches.occurrences_of("VERBOSE");
            let api_version = parse_pcs_version(matches.value_of("API_VERSION").unwrap_or(DEFAULT_API_VERSION))
                .expect("validated");

            let origin =
                parse_origin(matches.value_of("ORIGIN").unwrap_or(DEFAULT_ORIGIN)).expect("validated");

            let fetcher = match matches.is_present("INSECURE") {
                false => crate::reqwest_client(),
                true => crate::reqwest_client_insecure_tls(),
            };

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
                Origin::Pccs => {
                    let pccs_url = matches.value_of("PCCS_URL").expect("validated").to_owned();
                    let client_builder = PccsProvisioningClientBuilder::new(api_version, pccs_url);
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
