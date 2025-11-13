#![deny(warnings)]
use anyhow::{self, Context};
use log::{debug, info, warn};
use reqwest::blocking::Client;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

const BZIMAGE_X86_64_URL: &str = "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/ec130adc1fd86f2489f482d3f4a02676d3a748a7/blobs/x86_64/bzImage";
const BZIMAGE_X86_64_SHA256: &str =
    "210eda749c1308eb60671a579d24db5e8a3477cb7a247cf313c286b09fe2d857";
const BZIMAGE_CONFIG_X86_64_URL: &str = "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/ec130adc1fd86f2489f482d3f4a02676d3a748a7/blobs/x86_64/bzImage.config";
const BZIMAGE_CONFIG_X86_64_SHA256: &str =
    "9378dea490ed6c698c3d23b346ed08e49dae52d74a59cee2673b8a7b1951fc5b";
const CMDLINE_X86_64_URL: &str = "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/ec130adc1fd86f2489f482d3f4a02676d3a748a7/blobs/x86_64/cmdline";
const CMDLINE_X86_64_SHA256: &str =
    "10d7d9dd205d4596d45997d17434f26207525f129d171a51f9859b1af9f4a07a";
const INIT_X86_64_URL: &str = "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/ec130adc1fd86f2489f482d3f4a02676d3a748a7/blobs/x86_64/init";
const INIT_X86_64_SHA256: &str = "755e650b732777b798cb9ec243ee402bef4826f789cf01a1e453bb724207c005";
const NSM_X86_64_URL: &str = "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/ec130adc1fd86f2489f482d3f4a02676d3a748a7/blobs/x86_64/nsm.ko";
const NSM_X86_64_SHA256: &str = "48904e520db2541ca4378da29d85791749408febc81987ade56cc5c556bd90df";

struct Blob {
    url: &'static str,
    sha256: &'static str,
}

const BLOBS: [Blob; 5] = [
    Blob {
        url: BZIMAGE_X86_64_URL,
        sha256: BZIMAGE_X86_64_SHA256,
    },
    Blob {
        url: BZIMAGE_CONFIG_X86_64_URL,
        sha256: BZIMAGE_CONFIG_X86_64_SHA256,
    },
    Blob {
        url: CMDLINE_X86_64_URL,
        sha256: CMDLINE_X86_64_SHA256,
    },
    Blob {
        url: INIT_X86_64_URL,
        sha256: INIT_X86_64_SHA256,
    },
    Blob {
        url: NSM_X86_64_URL,
        sha256: NSM_X86_64_SHA256,
    },
];

impl Blob {
    fn download(&self, client: &Client, output_dir: &Path) -> anyhow::Result<PathBuf> {
        let filename = self
            .url
            .rsplit('/')
            .next()
            .context("Failed to get filename")?;
        let fullpath = output_dir.join(filename);
        if fullpath.exists() {
            let file_hash = Self::hash_file(&fullpath)?;
            match self.verify_hash(&file_hash) {
                Ok(_) => {
                    debug!("Hash of file {:?} verified.", fullpath);
                    return Ok(fullpath);
                }
                Err(_) => warn!("Hash check failed on {:?}, re-downloading ...", fullpath),
            }
        }

        info!("Downloading '{}' to {:?}", self.url, fullpath);
        let mut response = client.get(self.url).send()?;
        let mut fd = File::create(fullpath.clone())?;

        response.copy_to(&mut fd)?;
        // Close the file before calculating hash of it.
        drop(fd);

        let hash = Self::hash_file(&fullpath)?;
        self.verify_hash(&hash)
            .context("Expected hash mismatched")?;
        Ok(fullpath)
    }

    fn hash_file(path: &PathBuf) -> anyhow::Result<[u8; 32]> {
        let mut file = File::open(path)?;
        let mut hasher = Sha256::new();
        io::copy(&mut file, &mut hasher)?;
        let hash = hasher.finalize();
        Ok(hash.into())
    }

    fn verify_hash(&self, hash: &[u8]) -> anyhow::Result<()> {
        let expected = hex::decode(self.sha256)?;
        if expected != hash {
            anyhow::bail!("Hash check failed");
        }

        Ok(())
    }
}

pub fn download_blobs(output_dir: &Path) -> anyhow::Result<Vec<PathBuf>> {
    if !output_dir.is_dir() {
        anyhow::bail!("{:?} must be a directory.", output_dir);
    }

    let client = reqwest::blocking::Client::new();
    let mut blobs = Vec::new();
    for blob in &BLOBS {
        let blob_file = blob.download(&client, output_dir)?;
        blobs.push(blob_file);
    }

    Ok(blobs)
}
