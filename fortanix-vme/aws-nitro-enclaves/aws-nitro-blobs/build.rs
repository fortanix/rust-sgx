#![deny(warnings)]
use data_downloader::{DownloadRequest, Downloader};
use hex_literal::hex;
use std::env;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;

const NITRO_BLOBS: [(&str, DownloadRequest); 5] = [
    (
        r#"pub const KERNEL: &[u8] = include_bytes!("{path}");"#,
        DownloadRequest {
            url: "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/ec130adc1fd86f2489f482d3f4a02676d3a748a7/blobs/x86_64/bzImage",
            sha256_hash: &hex!("210eda749c1308eb60671a579d24db5e8a3477cb7a247cf313c286b09fe2d857"),
        },
    ),
    (
        r#"pub const KERNEL_CONFIG: &str = include_str!("{path}");"#,
        DownloadRequest {
            url: "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/ec130adc1fd86f2489f482d3f4a02676d3a748a7/blobs/x86_64/bzImage.config",
            sha256_hash: &hex!("9378dea490ed6c698c3d23b346ed08e49dae52d74a59cee2673b8a7b1951fc5b"),
        },
    ),
    (
        r#"pub const CMDLINE: &str = include_str!("{path}");"#,
        DownloadRequest {
            url: "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/ec130adc1fd86f2489f482d3f4a02676d3a748a7/blobs/x86_64/cmdline",
            sha256_hash: &hex!("10d7d9dd205d4596d45997d17434f26207525f129d171a51f9859b1af9f4a07a"),
        },
    ),
    (
        r#"pub const INIT: &[u8] = include_bytes!("{path}");"#,
        DownloadRequest {
            url: "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/ec130adc1fd86f2489f482d3f4a02676d3a748a7/blobs/x86_64/init",
            sha256_hash: &hex!("755e650b732777b798cb9ec243ee402bef4826f789cf01a1e453bb724207c005"),
        },
    ),
    (
        r#"pub const NSM: &[u8] = include_bytes!("{path}");"#,
        DownloadRequest {
            url: "https://raw.githubusercontent.com/aws/aws-nitro-enclaves-cli/ec130adc1fd86f2489f482d3f4a02676d3a748a7/blobs/x86_64/nsm.ko",
            sha256_hash: &hex!("48904e520db2541ca4378da29d85791749408febc81987ade56cc5c556bd90df"),
        },
    ),
];

fn main() {
    let mut out_dir = PathBuf::from(env::var("OUT_DIR").expect("OUT_DIR is missing"));
    let downloader = Downloader::builder()
        .storage_dir(out_dir.clone())
        .build()
        .expect("Unable to initialize downloader");

    let mut lines = Vec::with_capacity(NITRO_BLOBS.len());
    for (var, blob) in NITRO_BLOBS {
        let blob_path = downloader.get_path(&blob).unwrap();
        let line = var.replace("{path}", blob_path.to_str().unwrap());
        lines.push(line);
    }
    let lines = lines.join("\n");

    out_dir.push("nitro_blobs.rs");
    let mut fd = File::create(out_dir).expect("Unable to create nitro_blobs.rs file");
    fd.write_all(lines.as_bytes())
        .expect("Unable to write nitro_blobs.rs");

    println!("cargo:rerun-if-changed=build.rs");
}
