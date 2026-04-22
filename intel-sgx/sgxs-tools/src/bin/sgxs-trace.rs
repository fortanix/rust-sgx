#![cfg(unix)]

use clap::{App, Arg};
use nix::sys::ptrace;
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use sgxs::sgxs::{CanonicalSgxsWriter, Error, Meas, MeasECreate, MeasEExtend, MeasuredData, PageChunk, SecinfoTruncated, SgxsWrite};
use sgxs::sigstruct;
use sgxs_loaders::isgx::ioctl::*;
use std::cell::Cell;
use std::io::IoSliceMut;
use std::mem::size_of;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::fs::File;
use syscalls::Sysno;

thread_local!(static VERBOSE: Cell<bool> = Cell::new(false));

macro_rules! log {
    ($($arg:tt)*) => {
        if VERBOSE.get() { println!("[sgxs-trace] {}", format!($($arg)*)); }
    }
}

#[derive(Clone, Copy, Debug)]
struct AddPages {
    src: u64,
    offset: u64,
    length: u64,
    secinfo: u64,
    chunks: u16,  // 0x0000 = none, 0xffff = all, other = partial (single page)
}

#[derive(Clone, Copy, Debug)]
struct InitPages {
    sigstruct: *const sgx_isa::Sigstruct,
}

type ParseAddPagesFn = fn(&SGXSTracer, u64) -> anyhow::Result<AddPages>;
type ParseInitFn = fn(&SGXSTracer, u64) -> anyhow::Result<InitPages>;

struct SGXSWriter<'a> {
    path: PathBuf,
    file: *mut File,
    writer: CanonicalSgxsWriter<'a, File>,
    eadd: Option<AddPages>,
}

impl SGXSWriter<'_> {
    fn raw_writer(&mut self) -> &mut File {
        unsafe { &mut *self.file }
    }
}

impl Drop for SGXSWriter<'_> {
    fn drop(&mut self) {
        unsafe { drop(Box::from_raw(self.file)); }
    }
}
struct SGXSTracer {
    child: Pid,
    outdir: String,
    num: usize,
}

impl SGXSTracer {
    fn read_bytes(&self, addr: usize, len: usize) -> anyhow::Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        let mut local = [IoSliceMut::new(&mut buf)];
        let remote = [RemoteIoVec { base: addr, len }];
        process_vm_readv(self.child, &mut local, &remote)?;
        
        Ok(buf)
    }

    fn read_data<T>(&self, addr: usize) -> anyhow::Result<T> {
        let buf = self.read_bytes(addr, size_of::<T>())?;
        
        unsafe { Ok(std::ptr::read(buf.as_ptr() as *const T)) }
    }

    fn ioctl_ecreate(&self, arg: u64) -> anyhow::Result<SGXSWriter<'static>> {
        log!("SGX_IOC_ENCLAVE_CREATE");
        let cd: CreateData = self.read_data(arg as usize)?;
        let secs: sgx_isa::Secs = self.read_data(cd.secs as usize)?;
        log!("    L {:?}", secs);

        let path = Path::new(&self.outdir).join(format!("enclave{}.sgxs", self.num));
        let file = Box::leak(Box::new(File::create(&path)?));
        log!("Opened {:?}", file);

        let ecreate = MeasECreate { size: secs.size, ssaframesize: secs.ssaframesize };
        Ok(SGXSWriter { path: path.to_path_buf(), file: file, writer: CanonicalSgxsWriter::new(file, ecreate, true)?, eadd: None })
    }

    fn parse_add_montgomery(&self, arg: u64) -> anyhow::Result<AddPages> {
        let ad: montgomery::AddData = self.read_data(arg as usize)?;

        Ok(AddPages {
            src:     ad.srcpage as u64,
            offset:  ad.dstpage,
            length:  0x1000,
            secinfo: ad.secinfo as u64,
            chunks:  ad.chunks,
        })
    }

    fn parse_add_augusta(&self, arg: u64) -> anyhow::Result<AddPages> {
        let ad: augusta::AddData = self.read_data(arg as usize)?;

        Ok(AddPages {
            src:     ad.src as u64,
            offset:  ad.offset,
            length:  ad.length,
            secinfo: ad.secinfo as u64,
            chunks:  if ad.flags.contains(augusta::SgxPageFlags::SGX_PAGE_MEASURE) { 0xffff } else { 0x0000 },
        })
    }

    fn ioctl_eadd(&self, arg: u64, parse: ParseAddPagesFn, writer: &mut Option<SGXSWriter>) -> anyhow::Result<()> {
        log!("SGX_IOC_ENCLAVE_ADD_PAGES");
        let ad = parse(self, arg)?;
        let secinfo: sgx_isa::Secinfo = self.read_data(ad.secinfo as usize)?;
        log!("    L {:?}", ad);
        log!("    L {:?}", secinfo);

        anyhow::ensure!(ad.length % 0x1000 == 0, Error::StreamNotCanonical);
        let wr = writer.as_mut().ok_or(Error::StreamNotCanonical)?;
        let secinfo = SecinfoTruncated { flags: secinfo.flags };
        let bytes = self.read_bytes(ad.src as usize, ad.length as usize)?;
        let slice = &mut bytes.as_slice();

        match ad.chunks {
            0x0000 => {
                wr.writer.write_pages(None::<&mut &[u8]>, ad.length as usize / 0x1000, Some(ad.offset), secinfo)?
            }
            0xffff => {
                wr.writer.write_pages(Some(slice), ad.length as usize / 0x1000, Some(ad.offset), secinfo)?
            }
            _      => {
                // partial chunks: only possible for single page at a time (legacy montgomery drivers)
                let page_chunks = core::array::from_fn(|j| {
                    if ad.chunks & (1 << j) != 0 { PageChunk::IncludedMeasured } else { PageChunk::Skipped }
                });
                wr.writer.write_page(MeasuredData::from((slice, page_chunks)), Some(ad.offset), secinfo)?;
            }
        }

        wr.eadd = Some(ad);
        Ok(())
    }

    fn ioctl_eextend(&self, arg: u64, writer: &mut Option<SGXSWriter>) -> anyhow::Result<()> {
        log!("SGX_IOC_ENCLAVE_EXTEND");
        let ed: augusta::SgxEnclaveExtend = self.read_data(arg as usize)?;
        log!("    L {:?}", ed);

        // find data of previous EADD to be partially measured
        let wr = writer.as_mut().ok_or(Error::StreamNotCanonical)?;
        let ad = wr.eadd.ok_or(Error::StreamNotCanonical)?;
        anyhow::ensure!(ad.chunks == 0x0000, Error::StreamNotCanonical);
        anyhow::ensure!(ed.offset >= ad.offset, Error::StreamNotCanonical);
        anyhow::ensure!(ed.offset < ad.offset + ad.length, Error::StreamNotCanonical);

        // manually update the underlying stream with partially measured data
        let meas = MeasEExtend { offset: ed.offset};
        let bytes :[u8; 256] = self.read_data(ad.src as usize + ad.offset as usize)?;
        wr.raw_writer().write_meas(&Meas::EExtend { header: meas, data: bytes })?;

        Ok(())
    }

    fn parse_init_montgomery(&self, arg: u64) -> anyhow::Result<InitPages> {
        let id: montgomery::InitData = self.read_data(arg as usize)?;

        Ok(InitPages { sigstruct: id.sigstruct })
    }

    fn parse_init_montgomery_with_token(&self, arg: u64) -> anyhow::Result<InitPages> {
        let id: montgomery::InitDataWithToken = self.read_data(arg as usize)?;

        Ok(InitPages { sigstruct: id.sigstruct })
    }

    fn parse_init_augusta(&self, arg: u64) -> anyhow::Result<InitPages> {
        let id: augusta::InitData = self.read_data(arg as usize)?;
        
        Ok(InitPages { sigstruct: id.sigstruct })
    }

    fn ioctl_einit(&self, arg: u64, parse: ParseInitFn, writer: &mut Option<SGXSWriter>) -> anyhow::Result<()>  {
        log!("SGX_IOC_ENCLAVE_INIT");
        let id = parse(self, arg)?;
        let sigstruct: sgx_isa::Sigstruct = self.read_data(id.sigstruct as usize)?;
        log!("    L {:?}", sigstruct);
        log!("    L mrenclave: {}", hex::encode(sigstruct.enclavehash));

        // sanity-check if mrenclave hash of created SGXS file matches
        let path = &writer.as_ref().ok_or(Error::StreamNotCanonical)?.path;
        let hash = sigstruct::EnclaveHash::from_stream::<File, openssl::hash::Hasher>(&mut File::open(path)?)?.hash();
        if sigstruct.enclavehash != hash {
            eprintln!("|-- ERROR: mismatching hashes for {:?}", path);
            eprintln!("|--        sigstruct = {}", hex::encode(sigstruct.enclavehash));
            eprintln!("|--        sgxs      = {}", hex::encode(hash));
        }

        *writer = None;
        Ok(())
    }

    fn run(&mut self) -> anyhow::Result<()> {
        let child = self.child;
        let wait_for_stop = || -> bool {
            matches!(waitpid(child, None).ok(), Some(WaitStatus::Stopped(_, _)))
        };

        anyhow::ensure!(wait_for_stop(), "ptrace could not attach to child");
        ptrace::setoptions(self.child, ptrace::Options::PTRACE_O_EXITKILL)?;

        let mut writer: Option<SGXSWriter> = None;
        loop {
            ptrace::syscall(self.child, None)?;
            if !wait_for_stop() { break; }

            let regs = ptrace::getregs(self.child)?;
            let Some(sys) = Sysno::new(regs.orig_rax as usize) else { break; };
            if sys == Sysno::ioctl {
                match regs.rsi {
                    SGX_IOC_ENCLAVE_CREATE    => {
                        anyhow::ensure!(writer.is_none(), Error::StreamNotCanonical);
                        writer = Some(self.ioctl_ecreate(regs.rdx)?);
                        self.num += 1;
                    }
                    montgomery::SGX_IOC_ENCLAVE_ADD_PAGES => {
                        self.ioctl_eadd(regs.rdx, SGXSTracer::parse_add_montgomery, &mut writer)?;
                    }
                    augusta::SGX_IOC_ENCLAVE_ADD_PAGES => {
                        self.ioctl_eadd(regs.rdx, SGXSTracer::parse_add_augusta, &mut writer)?;
                    }
                    montgomery::SGX_IOC_ENCLAVE_INIT => {
                        self.ioctl_einit(regs.rdx, Self::parse_init_montgomery, &mut writer)?
                    }
                    montgomery::SGX_IOC_ENCLAVE_INIT_WITH_TOKEN => {
                        self.ioctl_einit(regs.rdx, Self::parse_init_montgomery_with_token, &mut writer)?
                    }
                    augusta::SGX_IOC_ENCLAVE_INIT => {
                        self.ioctl_einit(regs.rdx, Self::parse_init_augusta, &mut writer)?
                    }
                    augusta::SGX_IOC_ENCLAVE_EXTEND => {
                        self.ioctl_eextend(regs.rdx, &mut writer)?;
                    }
                    _ => {}
                }
            }
            
            ptrace::syscall(self.child, None)?;
            if !wait_for_stop() { break; }
        }

        anyhow::ensure!(writer.is_none(), Error::StreamNotCanonical);
        log!("exiting; extracted {} SGXS enclave{} to directory {}", self.num, if self.num > 1 {"s"} else {""}, self.outdir);
        Ok(())
    }
}

fn main() {
    let matches = App::new("sgxs-trace")
        .about("Extracts SGXS enclaves by tracing syscalls of a running process")
        .arg(Arg::with_name("prog").required(true).multiple(true).last(true)
            .help("Program and arguments to run"))
        .arg(Arg::with_name("outdir").short("o").long("output-dir").default_value(".")
            .help("Output directory for extracted SGXS files"))
        .arg(Arg::with_name("verbose").short("v").long("verbose")
            .help("Print verbose information about traced syscalls"))
        .get_matches();

    let mut args = matches.values_of("prog").unwrap();
    let cmd = args.next().unwrap();
    let outdir = matches.value_of("outdir").unwrap().to_string();
    VERBOSE.set(matches.is_present("verbose"));
    
    match unsafe { fork() }.expect("fork failed") {
        ForkResult::Child => {
            ptrace::traceme().unwrap();
            let err = Command::new(cmd).args(args).exec();
            panic!("child exec failed: {}", err);
        }
        ForkResult::Parent { child, .. } => {
            if let Err(e) = (SGXSTracer { child, outdir, num: 0 }).run() {
                panic!("error during tracing: {}", e);
            }
        }
    }
}