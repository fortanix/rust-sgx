use aws_nitro_blobs_downloader::download_blobs;
use std::env;
use std::path::Path;

fn main() {
    let out_dir = env::var("OUT_DIR").expect("OUT_DIR is missing");
    download_blobs(Path::new(&out_dir)).expect("Download nitro blobs failed");
}
