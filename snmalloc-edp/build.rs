use std::fs::{DirEntry, File};
use std::path::{Path, PathBuf};

fn files_in_dir(p: &Path) -> impl Iterator<Item = DirEntry> {
    p.read_dir().unwrap().map(|e| e.unwrap()).filter(|e| e.file_type().unwrap().is_file())
}

fn main() {
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());

    // # Use CMake to build the shim
    let mut dst = cmake::build(".");
    dst.push("build");
    println!("cargo:rustc-link-search=native={}", dst.display());

    // ideally, the cmake crate would have a way to output this
    println!("cargo:rerun-if-changed=CMakeLists.txt");
    println!("cargo:rerun-if-changed=src/rust-sgx-snmalloc-shim.cpp");

    // # Extract the static library archive into a temporary directory
    let mut objs = out_dir.clone();
    objs.push("objs");
    std::fs::create_dir_all(&objs).unwrap();
    // clear existing files in the temp dir
    for file in files_in_dir(&objs) {
        std::fs::remove_file(file.path()).unwrap();
    }

    dst.push("libsnmalloc-edp.a");

    let mut ar = cc::Build::new().get_archiver();
    ar.args(&["x", "--output"]);
    ar.arg(&objs);
    ar.arg(dst);
    assert!(ar.status().unwrap().success());

    // # Read the symbols from the shim ELF object
    let f = files_in_dir(&objs).next().unwrap();
    let mut elf = elf::ElfStream::<elf::endian::LittleEndian, _>::open_stream(File::open(f.path()).unwrap()).unwrap();
    let (symtab, strtab) = elf.symbol_table().unwrap().unwrap();
    let mut sn_alloc_size = None;
    let mut sn_alloc_align = None;
    for sym in symtab {
        match strtab.get(sym.st_name as _).unwrap() {
            "sn_alloc_size" => assert!(sn_alloc_size.replace(sym).is_none()),
            "sn_alloc_align" => assert!(sn_alloc_align.replace(sym).is_none()),
            _ => {}
        }
    }
    let sn_alloc_size = sn_alloc_size.expect("sn_alloc_size");
    let sn_alloc_align = sn_alloc_align.expect("sn_alloc_align");

    let mut get_u64_at_symbol = |sym: elf::symbol::Symbol| {
        assert_eq!(sym.st_size, 8);
        let (data, _) = elf.section_data(&elf.section_headers()[sym.st_shndx as usize].clone()).unwrap();
        let data: &[u8; 8] = data.split_at(8).0.try_into().unwrap();
        u64::from_le_bytes(*data)
    };

    let sn_alloc_size = get_u64_at_symbol(sn_alloc_size);
    let sn_alloc_align = get_u64_at_symbol(sn_alloc_align);

    // # Write the type
    let contents = format!("#[repr(align({}), C)] pub struct Alloc {{ _0: [u8; {}] }}", sn_alloc_align, sn_alloc_size);
    let mut alloc_type_rs = out_dir.clone();
    alloc_type_rs.push("alloc-type.rs");
    std::fs::write(alloc_type_rs, contents).unwrap();
}
