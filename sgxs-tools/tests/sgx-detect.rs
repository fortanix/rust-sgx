use std::env;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::Command;

use regex::Regex;

fn sgx_detect_bin_path() -> PathBuf {
    let mut testbin = PathBuf::from(env::args_os().next().unwrap());
    assert!(testbin.pop());
    assert_eq!(testbin.file_name().unwrap(), "deps");
    assert!(testbin.pop());
    testbin.push("sgx-detect");
    testbin
}

fn ui_tests_dir() -> PathBuf {
    let mut path = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    path.push("tests");
    path.push("data");
    path.push("sgx_detect");
    path
}

fn parse_tests(path: &PathBuf) -> Vec<(Regex, bool)> {
    BufReader::new(File::open(path).unwrap()).lines().map(Result::unwrap).map(|line| {
        let invert = line.starts_with("~");
        (Regex::new(&line[(invert as usize)..]).unwrap(), invert)
    }).collect()
}

#[test]
fn debug_help() {
    let mut failures = 0;

    let path = sgx_detect_bin_path();
    for entry in ui_tests_dir()
        .read_dir()
        .unwrap()
        .map(Result::unwrap)
        .filter(|entry| entry.file_name().to_string_lossy().ends_with(".yaml"))
    {
        let mut entry = entry.path();

        let output = Command::new(&path).arg("--test").arg(&entry).output().unwrap();
        let output = String::from_utf8(output.stdout).unwrap();

        assert!(entry.set_extension("test"));
        let tests = parse_tests(&entry);

        if let Some((re, invres)) = tests.into_iter().find(|&(ref re, invres)| re.is_match(&output) == invres) {
            failures += 1;
            assert!(entry.set_extension(""));
            println!("test `{}` failed.\nOutput:", entry.file_name().unwrap().to_string_lossy());
            for line in output.lines() {
                println!("    {}", line);
            }
            if invres {
                println!("Regular expression matched unexpectedly:\n    {}", re);
            } else {
                println!("Expected to find regular expression:\n    {}", re);
            }
        }
    }

    if failures != 0 {
        panic!("{} failures", failures);
    }
}
