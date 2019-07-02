/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate libc;
#[cfg(unix)]
extern crate nix;

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::RefCell;
use std::collections::VecDeque;
use std::fmt;
use std::io::{self, ErrorKind as IoErrorKind, Read, Result as IoResult, Write};
use std::net::{TcpListener, TcpStream};
use std::result::Result as StdResult;
use std::str;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use std::sync::mpsc::{self, channel, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time;

use failure;
use fnv::FnvHashMap;

use fortanix_sgx_abi::*;
use sgxs::loader::Tcs as SgxsTcs;

lazy_static! {
    static ref DEBUGGER_TOGGLE_SYNC: Mutex<()> = Mutex::new(());
}

pub(crate) mod abi;
mod interface;

use self::abi::dispatch;
use self::interface::{Handler, OutputBuffer};
#[cfg(unix)]
use self::libc::*;
#[cfg(unix)]
use self::nix::sys::signal;
use crate::loader::{EnclavePanic, ErasedTcs};
use std::thread::JoinHandle;
use crate::tcs;
use crate::tcs::{CoResult, ThreadResult};

const EV_ABORT: u64 = 0b0000_0000_0000_1000;

struct ReadOnly<R>(R);
struct WriteOnly<W>(W);

type UsercallSendData = (ThreadResult<ErasedTcs>, RunningTcs, RefCell<[u8; 1024]>);
macro_rules! forward {
    (fn $n:ident(&mut self $(, $p:ident : $t:ty)*) -> $ret:ty) => {
        fn $n(&mut self $(, $p: $t)*) -> $ret {
            self.0 .$n($($p),*)
        }
    }
}

impl<R: Read> Read for ReadOnly<R> {
    forward!(fn read(&mut self, buf: &mut [u8]) -> IoResult<usize>);
}

impl<T> Read for WriteOnly<T> {
    fn read(&mut self, _buf: &mut [u8]) -> IoResult<usize> {
        Err(IoErrorKind::BrokenPipe.into())
    }
}

impl<T> Write for ReadOnly<T> {
    fn write(&mut self, _buf: &[u8]) -> IoResult<usize> {
        Err(IoErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> IoResult<()> {
        Err(IoErrorKind::BrokenPipe.into())
    }
}

impl<W: Write> Write for WriteOnly<W> {
    forward!(fn write(&mut self, buf: &[u8]) -> IoResult<usize>);
    forward!(fn flush(&mut self) -> IoResult<()>);
}

trait SharedStream<'a> {
    type Inner: Read + Write + 'a;

    fn lock(&'a self) -> Self::Inner;
}

struct Shared<T>(T);

impl<'a, T: SharedStream<'a>> Read for &'a Shared<T> {
    fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
        self.0.lock().read(buf)
    }
}

impl<'a, T: SharedStream<'a>> Write for &'a Shared<T> {
    fn write(&mut self, buf: &[u8]) -> IoResult<usize> {
        self.0.lock().write(buf)
    }

    fn flush(&mut self) -> IoResult<()> {
        self.0.lock().flush()
    }
}

impl<'a> SharedStream<'a> for io::Stdin {
    type Inner = ReadOnly<io::StdinLock<'a>>;

    fn lock(&'a self) -> Self::Inner {
        ReadOnly(io::Stdin::lock(self))
    }
}

impl<'a> SharedStream<'a> for io::Stdout {
    type Inner = WriteOnly<io::StdoutLock<'a>>;

    fn lock(&'a self) -> Self::Inner {
        WriteOnly(io::Stdout::lock(self))
    }
}

impl<'a> SharedStream<'a> for io::Stderr {
    type Inner = WriteOnly<io::StderrLock<'a>>;

    fn lock(&'a self) -> Self::Inner {
        WriteOnly(io::Stderr::lock(self))
    }
}

impl<S: 'static + Send + Sync> SyncStream for S
where
    for<'a> &'a S: Read + Write,
{
    fn read(&self, buf: &mut [u8]) -> IoResult<usize> {
        Read::read(&mut { self }, buf)
    }

    fn write(&self, buf: &[u8]) -> IoResult<usize> {
        Write::write(&mut { self }, buf)
    }

    fn flush(&self) -> IoResult<()> {
        Write::flush(&mut { self })
    }
}

/// This trait is mostly same as `std::io::Read` + `std::io::Write` except that it takes an immutable reference to the source.
pub trait SyncStream: 'static + Send + Sync {
    /// Read some data from stream, letting the callee choose the amount.
    fn read_alloc(&self) -> IoResult<Vec<u8>> {
        let mut buf = vec![0; 8192];
        let len = self.read(&mut buf)?;
        buf.resize(len, 0);
        Ok(buf)
    }

    /// Same as `std::io::Read::read`, except that it takes an immutable reference to the source.
    fn read(&self, buf: &mut [u8]) -> IoResult<usize>;
    /// Same as `std::io::Write::write` , except that it takes an immutable reference to the source.
    fn write(&self, buf: &[u8]) -> IoResult<usize>;
    /// Same as `std::io::Write::flush` , except that it takes an immutable reference to the source.
    fn flush(&self) -> IoResult<()>;
}

/// SyncListener lets an implementation implement a slightly modified form of `std::net::TcpListener::accept`.
pub trait SyncListener: 'static + Send + Sync {
    /// The enclave may optionally request the local or peer addresses
    /// be returned in `local_addr` or `peer_addr`, respectively.
    /// If `local_addr` and/or `peer_addr` are not `None`, they will point to an empty `String`.
    /// On success, user-space can fill in the strings as appropriate.
    ///
    /// The enclave must not make any security decisions based on the local address received.
    fn accept(
        &self,
        local_addr: Option<&mut String>,
        peer_addr: Option<&mut String>,
    ) -> IoResult<Box<dyn SyncStream>>;
}

impl SyncListener for TcpListener {
    fn accept(
        &self,
        local_addr: Option<&mut String>,
        peer_addr: Option<&mut String>,
    ) -> IoResult<Box<dyn SyncStream>> {
        TcpListener::accept(self).map(|(s, peer)| {
            if let Some(local_addr) = local_addr {
                match self.local_addr() {
                    Ok(local) => *local_addr = local.to_string(),
                    Err(_) => *local_addr = "error".to_string(),
                }
            }
            if let Some(peer_addr) = peer_addr {
                *peer_addr = peer.to_string();
            }
            Box::new(s) as _
        })
    }
}

enum FileDesc {
    Stream(Box<dyn SyncStream>),
    Listener(Box<dyn SyncListener>),
}

impl FileDesc {
    fn stream<S: SyncStream>(s: S) -> FileDesc {
        FileDesc::Stream(Box::new(s))
    }

    fn listener<L: SyncListener>(l: L) -> FileDesc {
        FileDesc::Listener(Box::new(l))
    }

    fn as_stream(&self) -> IoResult<&dyn SyncStream> {
        if let FileDesc::Stream(ref s) = self {
            Ok(&**s)
        } else {
            Err(IoErrorKind::InvalidInput.into())
        }
    }

    fn as_listener(&self) -> IoResult<&dyn SyncListener> {
        if let FileDesc::Listener(ref l) = self {
            Ok(&**l)
        } else {
            Err(IoErrorKind::InvalidInput.into())
        }
    }
}

#[derive(Debug)]
pub(crate) enum EnclaveAbort<T> {
    Exit {
        panic: T,
    },
    /// Secondary threads exiting due to an abort
    Secondary,
    IndefiniteWait,
    InvalidUsercall(u64),
    MainReturned,
}

#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
struct TcsAddress(usize);

impl ErasedTcs {
    fn address(&self) -> TcsAddress {
        TcsAddress(SgxsTcs::address(self) as _)
    }
}

impl fmt::Pointer for TcsAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        (self.0 as *const u8).fmt(f)
    }
}

struct StoppedTcs {
    tcs: ErasedTcs,
    event_queue: Receiver<u8>,
}

struct IOHandlerInput<'a> {
    tcs: &'a mut RunningTcs,
    enclave: &'a EnclaveState,
    work_sender: &'a crossbeam::crossbeam_channel::Sender<Work>,
}

struct RunningTcs {
    pending_event_set: u8,
    pending_events: VecDeque<u8>,
    event_queue: Receiver<u8>,
    mode: EnclaveEntry,
}

enum EnclaveKind {
    Command(Command),
    Library(Library),
}

struct PanicReason {
    primary_panic_reason: Option<EnclaveAbort<EnclavePanic>>,
    other_reasons: Vec<EnclaveAbort<EnclavePanic>>,
}

struct Command {
    panic_reason: Mutex<PanicReason>,
}

struct Library {}

impl EnclaveKind {
    fn as_command(&self) -> Option<&Command> {
        match self {
            EnclaveKind::Command(c) => Some(c),
            _ => None,
        }
    }

    fn _as_library(&self) -> Option<&Library> {
        match self {
            EnclaveKind::Library(l) => Some(l),
            _ => None,
        }
    }
}

pub(crate) struct EnclaveState {
    kind: EnclaveKind,
    event_queues: FnvHashMap<TcsAddress, Mutex<Sender<u8>>>,
    fds: Mutex<FnvHashMap<Fd, Arc<FileDesc>>>,
    last_fd: AtomicUsize,
    exiting: AtomicBool,
    usercall_ext: Box<dyn UsercallExtension>,
    threads_queue: crossbeam::queue::SegQueue<StoppedTcs>,
}

struct Work {
    tcs: RunningTcs,
    entry: CoEntry,
}

enum CoEntry {
    Initial(ErasedTcs, u64, u64, u64, u64, u64),
    Resume(tcs::Usercall<ErasedTcs>, (u64, u64)),
}

impl Work {
    fn do_work(self, io_send_queue: &mpsc::Sender<UsercallSendData>) {
        let buf = RefCell::new([0u8; 1024]);
        let usercall_send_data = match self.entry {
            CoEntry::Initial(erased_tcs, p1, p2, p3, p4, p5) => {
                let coresult = tcs::coenter(erased_tcs, p1, p2, p3, p4, p5, Some(&buf));
                ((coresult, self.tcs, buf))
            }
            CoEntry::Resume(usercall, coresult) => {
                let coresult = usercall.coreturn(coresult, Some(&buf));
                ((coresult, self.tcs, buf))
            }
        };
        // if there is an error do nothing, as it means that the main thread has exited
        let _ = io_send_queue.send(usercall_send_data);
    }
}

impl EnclaveState {
    fn event_queue_add_tcs(
        event_queues: &mut FnvHashMap<TcsAddress, Mutex<Sender<u8>>>,
        tcs: ErasedTcs,
    ) -> StoppedTcs {
        let (send, recv) = channel();
        if event_queues
            .insert(tcs.address(), Mutex::new(send))
            .is_some()
        {
            panic!("duplicate TCS address: {:p}", tcs.address())
        }
        StoppedTcs {
            tcs,
            event_queue: recv,
        }
    }

    fn new(
        kind: EnclaveKind,
        mut event_queues: FnvHashMap<TcsAddress, Mutex<Sender<u8>>>,
        usercall_ext: Option<Box<dyn UsercallExtension>>,
        threads_vector: Vec<ErasedTcs>,
    ) -> Arc<Self> {
        let mut fds = FnvHashMap::default();
        fds.insert(FD_STDIN, Arc::new(FileDesc::stream(Shared(io::stdin()))));
        fds.insert(FD_STDOUT, Arc::new(FileDesc::stream(Shared(io::stdout()))));
        fds.insert(FD_STDERR, Arc::new(FileDesc::stream(Shared(io::stderr()))));
        let last_fd = AtomicUsize::new(fds.keys().cloned().max().unwrap() as _);

        let usercall_ext = usercall_ext.unwrap_or_else(|| Box::new(UsercallExtensionDefault));

        let threads_queue = crossbeam::queue::SegQueue::new();

        for thread in threads_vector {
            threads_queue.push(Self::event_queue_add_tcs(&mut event_queues, thread));
        }

        Arc::new(EnclaveState {
            kind,
            event_queues,
            fds: Mutex::new(fds),
            last_fd,
            exiting: AtomicBool::new(false),
            usercall_ext,
            threads_queue,
        })
    }

    fn syscall_loop(
        &self,
        io_queue_receive: mpsc::Receiver<UsercallSendData>,
        work_sender: crossbeam::crossbeam_channel::Sender<Work>,
    ) -> StdResult<(u64, u64), EnclaveAbort<EnclavePanic>> {
        while let Ok((coresult, mut state, buf)) = io_queue_receive.recv() {
            let my_result = match coresult {
                CoResult::Yield(usercall) => {
                    let result = {
                        let mut input = IOHandlerInput {
                            enclave: &self,
                            tcs: &mut state,
                            work_sender: &work_sender,
                        };
                        let (p1, p2, p3, p4, p5) = usercall.parameters();
                        dispatch(&mut Handler(&mut input), p1, p2, p3, p4, p5)
                    };
                    match result {
                        Ok(ret) => {
                            work_sender
                                .send(Work {
                                    tcs: state,
                                    entry: CoEntry::Resume(usercall, ret),
                                })
                                .expect("Work sender couldn't send data to receiver");
                            continue;
                        }
                        Err(EnclaveAbort::Exit { panic: true }) => {
                            #[cfg(unix)]
                            trap_attached_debugger(usercall.tcs_address() as _);
                            Err(EnclaveAbort::Exit {
                                panic: EnclavePanic::from(buf.into_inner()),
                            })
                        }
                        Err(EnclaveAbort::Exit { panic: false }) => Ok((0, 0)),
                        Err(EnclaveAbort::IndefiniteWait) => Err(EnclaveAbort::IndefiniteWait),
                        Err(EnclaveAbort::InvalidUsercall(n)) => {
                            Err(EnclaveAbort::InvalidUsercall(n))
                        }
                        Err(EnclaveAbort::MainReturned) => Err(EnclaveAbort::MainReturned),
                        Err(EnclaveAbort::Secondary) => Err(EnclaveAbort::Secondary),
                    }
                }
                CoResult::Return((tcs, v1, v2)) => {
                    match state.mode {
                        EnclaveEntry::Library => {
                            self.threads_queue.push(StoppedTcs {
                                tcs,
                                event_queue: state.event_queue,
                            });
                            Ok((v1, v2))
                        }
                        EnclaveEntry::ExecutableMain => {
                            return Err(EnclaveAbort::MainReturned);
                        }
                        EnclaveEntry::ExecutableNonMain => {
                            assert_eq!(
                                (v1, v2),
                                (0, 0),
                                "Expected enclave thread entrypoint to return zero"
                            );
                            // If the enclave is in the exit-state, threads are no
                            // longer able to be launched
                            if !self.exiting.load(Ordering::SeqCst) {
                                self.threads_queue.push(StoppedTcs {
                                    tcs,
                                    event_queue: state.event_queue,
                                });
                            }
                            Ok((0, 0))
                        }
                    }
                }
            };

            match (my_result, state.mode) {
                (e, EnclaveEntry::Library)
                | (e, EnclaveEntry::ExecutableMain)
                | (e @ Err(EnclaveAbort::Secondary), EnclaveEntry::ExecutableNonMain) => return e,
                (Ok(_), EnclaveEntry::ExecutableNonMain) => {
                    continue;
                }
                (Err(e @ EnclaveAbort::Exit { .. }), EnclaveEntry::ExecutableNonMain)
                | (Err(e @ EnclaveAbort::InvalidUsercall(_)), EnclaveEntry::ExecutableNonMain) => {
                    let cmd = self.kind.as_command().unwrap();
                    let mut cmddata = cmd.panic_reason.lock().unwrap();

                    if cmddata.primary_panic_reason.is_none() {
                        cmddata.primary_panic_reason = Some(e)
                    } else {
                        cmddata.other_reasons.push(e)
                    }
                    return Err(EnclaveAbort::Secondary);
                }
                (Err(e), EnclaveEntry::ExecutableNonMain) => {
                    let cmd = self.kind.as_command().unwrap();
                    let mut cmddata = cmd.panic_reason.lock().unwrap();
                    cmddata.other_reasons.push(e)
                }
            }
        }
        unreachable!();
    }

    fn run(
        &self,
        num_of_worker_threads: usize,
        start_work: Work,
    ) -> StdResult<(u64, u64), EnclaveAbort<EnclavePanic>> {
        fn create_worker_threads(
            num_of_worker_threads: usize,
            work_receiver: crossbeam::crossbeam_channel::Receiver<Work>,
            io_queue_send: mpsc::Sender<UsercallSendData>,
        ) -> Vec<JoinHandle<()>> {
            let mut thread_handles = vec![];
            for _ in 0..num_of_worker_threads {
                let work_receiver = work_receiver.clone();
                let io_queue_send = io_queue_send.clone();

                thread_handles.push(thread::spawn(move || {
                    while let Ok(work) = work_receiver.recv() {
                        work.do_work(&io_queue_send);
                    }
                }));
            }
            return thread_handles;
        }

        let (io_queue_send, io_queue_receive) = mpsc::channel();

        let (work_sender, work_receiver) = crossbeam::crossbeam_channel::unbounded();
        work_sender
            .send(start_work)
            .expect("Work sender couldn't send data to receiver");

        let join_handlers =
            create_worker_threads(num_of_worker_threads, work_receiver, io_queue_send);
        // main syscall polling loop
        let main_result = self.syscall_loop(io_queue_receive, work_sender);

        for handler in join_handlers {
            let _ = handler.join();
        }
        return main_result;
    }

    pub(crate) fn main_entry(
        main: ErasedTcs,
        threads: Vec<ErasedTcs>,
        usercall_ext: Option<Box<dyn UsercallExtension>>,
    ) -> StdResult<(), failure::Error> {
        let mut event_queues =
            FnvHashMap::with_capacity_and_hasher(threads.len() + 1, Default::default());
        let main = Self::event_queue_add_tcs(&mut event_queues, main);

        let main_work = Work {
            tcs: RunningTcs {
                event_queue: main.event_queue,
                pending_event_set: 0,
                pending_events: Default::default(),
                mode: EnclaveEntry::ExecutableMain,
            },
            entry: CoEntry::Initial(main.tcs, 0, 0, 0, 0, 0),
        };

        let num_of_threads = num_cpus::get();

        let kind = EnclaveKind::Command(Command {
            panic_reason: Mutex::new(PanicReason {
                primary_panic_reason: None,
                other_reasons: vec![],
            }),
        });
        let enclave = EnclaveState::new(kind, event_queues, usercall_ext, threads);

        let main_result = enclave.run(num_of_threads, main_work);

        let main_panicking = match main_result {
            Err(EnclaveAbort::MainReturned)
            | Err(EnclaveAbort::InvalidUsercall(_))
            | Err(EnclaveAbort::Exit { .. }) => true,
            Err(EnclaveAbort::IndefiniteWait) | Err(EnclaveAbort::Secondary) | Ok(_) => false,
        };

        enclave.abort_all_threads();
        //clear the threads_queue
        while enclave.threads_queue.pop().is_ok() {}

        let cmd = enclave.kind.as_command().unwrap();
        let mut cmddata = cmd.panic_reason.lock().unwrap();
        let main_result = match (main_panicking, cmddata.primary_panic_reason.take()) {
            (false, Some(reason)) => Err(reason),
            // TODO: interpret other_reasons
            _ => main_result,
        };
        match main_result {
            Err(EnclaveAbort::Exit { panic }) => Err(panic.into()),
            Err(EnclaveAbort::IndefiniteWait) => {
                bail!("All enclave threads are waiting indefinitely without possibility of wakeup")
            }
            Err(EnclaveAbort::InvalidUsercall(n)) => {
                bail!("The enclave performed an invalid usercall 0x{:x}", n)
            }
            Err(EnclaveAbort::MainReturned) => bail!(
                "The enclave returned from the main entrypoint in violation of the specification."
            ),
            // Should always be able to return the real exit reason
            Err(EnclaveAbort::Secondary) => unreachable!(),
            Ok(_) => Ok(()),
        }
    }

    pub(crate) fn library(
        threads: Vec<ErasedTcs>,
        usercall_ext: Option<Box<dyn UsercallExtension>>,
    ) -> Arc<Self> {
        let event_queues = FnvHashMap::with_capacity_and_hasher(threads.len(), Default::default());

        let kind = EnclaveKind::Library(Library {});

        let enclave = EnclaveState::new(kind, event_queues, usercall_ext, threads);
        return enclave;
    }

    pub(crate) fn library_entry(
        enclave: &Arc<Self>,
        p1: u64,
        p2: u64,
        p3: u64,
        p4: u64,
        p5: u64,
    ) -> StdResult<(u64, u64), failure::Error> {
        let thread = enclave.threads_queue.pop().expect("threads queue empty");
        let work = Work {
            tcs: RunningTcs {
                event_queue: thread.event_queue,
                mode: EnclaveEntry::Library,
                pending_event_set: 0,
                pending_events: Default::default(),
            },
            entry: CoEntry::Initial(thread.tcs, p1, p2, p3, p4, p5),
        };
        // As currently we are not supporting spawning threads let the number of threads be 2
        // one for usercall handling the other for actually running
        let num_of_worker_threads = 1;

        let library_result = enclave.run(num_of_worker_threads, work);

        match library_result {
            Err(EnclaveAbort::Exit { panic }) => Err(panic.into()),
            Err(EnclaveAbort::IndefiniteWait) => {
                bail!("This thread is waiting indefinitely without possibility of wakeup")
            }
            Err(EnclaveAbort::InvalidUsercall(n)) => {
                bail!("The enclave performed an invalid usercall 0x{:x}", n)
            }
            Err(EnclaveAbort::Secondary) => {
                bail!("This thread exited because another thread aborted")
            }
            Err(EnclaveAbort::MainReturned) => unreachable!(),
            Ok(result) => Ok(result),
        }
    }

    fn abort_all_threads(&self) {
        self.exiting.store(true, Ordering::SeqCst);
        // wake other threads
        for queue in self.event_queues.values() {
            let _ = queue.lock().unwrap().send(EV_ABORT as _);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum EnclaveEntry {
    ExecutableMain,
    ExecutableNonMain,
    Library,
}

#[repr(C)]
#[allow(unused)]
enum Greg {
    R8 = 0,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    RDI,
    RSI,
    RBP,
    RBX,
    RDX,
    RAX,
    RCX,
    RSP,
    RIP,
    EFL,
    CSGSFS, /* Actually short cs, gs, fs, __pad0. */
    ERR,
    TRAPNO,
    OLDMASK,
    CR2,
}

#[cfg(unix)]
/* Here we are passing control to debugger `fixup` style by raising Sigtrap.
 * If there is no debugger attached, this function, would skip the `int3` instructon
 * and resume execution.
 */
extern "C" fn handle_trap(_signo: c_int, _info: *mut siginfo_t, context: *mut c_void) {
    unsafe {
        let context = &mut *(context as *mut ucontext_t);
        let rip = &mut context.uc_mcontext.gregs[Greg::RIP as usize];
        let inst: *const u8 = *rip as _;
        if *inst == 0xcc {
            *rip += 1;
        }
    }
    return;
}

#[cfg(unix)]
/* Raising Sigtrap to allow debugger to take control.
 * Here, we also store tcs in rbx, so that the debugger could read it, to
 * set sgx state and correctly map the enclave symbols.
 */
fn trap_attached_debugger(tcs: usize) {
    let _g = DEBUGGER_TOGGLE_SYNC.lock().unwrap();
    let hdl = self::signal::SigHandler::SigAction(handle_trap);
    let sig_action = signal::SigAction::new(hdl, signal::SaFlags::empty(), signal::SigSet::empty());
    // Synchronized
    unsafe {
        let old = signal::sigaction(signal::SIGTRAP, &sig_action).unwrap();
        asm!("int3" : /* No output */
                    : /*input */ "{rbx}"(tcs)
                    :/* No clobber */
                    :"volatile");
        signal::sigaction(signal::SIGTRAP, &old).unwrap();
    }
}

/// Provides a mechanism for the enclave code to interface with an external service via a modified runner.
///
/// An implementation of `UsercallExtension` can be registered while [building](../struct.EnclaveBuilder.html#method.usercall_extension) the enclave.

pub trait UsercallExtension: 'static + Send + Sync + std::fmt::Debug {
    /// Override the connection target for connect calls by the enclave. The runner should determine the service that the enclave is trying to connect to by looking at addr.
    /// If `connect_stream` returns None, the default implementation of [`connect_stream`](../../fortanix_sgx_abi/struct.Usercalls.html#method.connect_stream) is used.
    /// The enclave may optionally request the local or peer addresses
    /// be returned in `local_addr` or `peer_addr`, respectively.
    /// If `local_addr` and/or `peer_addr` are not `None`, they will point to an empty `String`.
    /// On success, user-space can fill in the strings as appropriate.
    ///
    /// The enclave must not make any security decisions based on the local or
    /// peer address received.
    #[allow(unused)]
    fn connect_stream(
        &self,
        addr: &str,
        local_addr: Option<&mut String>,
        peer_addr: Option<&mut String>,
    ) -> IoResult<Option<Box<dyn SyncStream>>> {
        Ok(None)
    }

    /// Override the target for bind calls by the enclave. The runner should determine the service that the enclave is trying to bind to by looking at addr.
    /// If `bind_stream` returns None, the default implementation of [`bind_stream`](../../fortanix_sgx_abi/struct.Usercalls.html#method.bind_stream) is used.
    /// The enclave may optionally request the local address be returned in `local_addr`.
    /// If `local_addr` is not `None`, it will point to an empty `String`.
    /// On success, user-space can fill in the string as appropriate.
    ///
    /// The enclave must not make any security decisions based on the local address received.
    #[allow(unused)]
    fn bind_stream(
        &self,
        addr: &str,
        local_addr: Option<&mut String>,
    ) -> IoResult<Option<Box<dyn SyncListener>>> {
        Ok(None)
    }
}

impl<T: UsercallExtension> From<T> for Box<dyn UsercallExtension> {
    fn from(value: T) -> Box<dyn UsercallExtension> {
        Box::new(value)
    }
}

#[derive(Debug)]
struct UsercallExtensionDefault;
impl UsercallExtension for UsercallExtensionDefault {}

#[allow(unused_variables)]
impl<'a> IOHandlerInput<'a> {
    fn lookup_fd(&self, fd: Fd) -> IoResult<Arc<FileDesc>> {
        match self.enclave.fds.lock().unwrap().get(&fd) {
            Some(stream) => Ok(stream.clone()),
            None => Err(IoErrorKind::BrokenPipe.into()), // FIXME: Rust normally maps Unix EBADF to `Other`
        }
    }

    fn alloc_fd(&self, stream: FileDesc) -> Fd {
        let fd = (self
            .enclave
            .last_fd
            .fetch_add(1, Ordering::Relaxed)
            .checked_add(1)
            .expect("FD overflow")) as Fd;
        let prev = self
            .enclave
            .fds
            .lock()
            .unwrap()
            .insert(fd, Arc::new(stream));
        debug_assert!(prev.is_none());
        fd
    }

    #[inline(always)]
    fn is_exiting(&self) -> bool {
        self.enclave.exiting.load(Ordering::SeqCst)
    }

    #[inline(always)]
    fn read(&self, fd: Fd, buf: &mut [u8]) -> IoResult<usize> {
        self.lookup_fd(fd)?.as_stream()?.read(buf)
    }

    #[inline(always)]
    fn read_alloc(&self, fd: Fd, buf: &mut OutputBuffer) -> IoResult<()> {
        let v = self.lookup_fd(fd)?.as_stream()?.read_alloc()?;
        buf.set(v);
        Ok(())
    }

    #[inline(always)]
    fn write(&self, fd: Fd, buf: &[u8]) -> IoResult<usize> {
        self.lookup_fd(fd)?.as_stream()?.write(buf)
    }

    #[inline(always)]
    fn flush(&self, fd: Fd) -> IoResult<()> {
        self.lookup_fd(fd)?.as_stream()?.flush()
    }

    #[inline(always)]
    fn close(&self, fd: Fd) {
        self.enclave.fds.lock().unwrap().remove(&fd);
    }

    #[inline(always)]
    fn bind_stream(&self, addr: &[u8], local_addr: Option<&mut OutputBuffer>) -> IoResult<Fd> {
        let addr = str::from_utf8(addr).map_err(|_| IoErrorKind::ConnectionRefused)?;
        let mut local_addr_str = local_addr.as_ref().map(|_| String::new());
        if let Some(stream_ext) = self
            .enclave
            .usercall_ext
            .bind_stream(&addr, local_addr_str.as_mut())?
        {
            if let Some(local_addr) = local_addr {
                local_addr.set(local_addr_str.unwrap().into_bytes());
            }
            return Ok(self.alloc_fd(FileDesc::Listener(stream_ext)));
        }
        let socket = TcpListener::bind(addr)?;
        if let Some(local_addr) = local_addr {
            local_addr.set(socket.local_addr()?.to_string().into_bytes())
        }
        Ok(self.alloc_fd(FileDesc::listener(socket)))
    }

    #[inline(always)]
    fn accept_stream(
        &self,
        fd: Fd,
        local_addr: Option<&mut OutputBuffer>,
        peer_addr: Option<&mut OutputBuffer>,
    ) -> IoResult<Fd> {
        let mut local_addr_str = local_addr.as_ref().map(|_| String::new());
        let mut peer_addr_str = peer_addr.as_ref().map(|_| String::new());

        let stream = self
            .lookup_fd(fd)?
            .as_listener()?
            .accept(local_addr_str.as_mut(), peer_addr_str.as_mut())?;
        if let Some(local_addr) = local_addr {
            local_addr.set(&local_addr_str.unwrap().into_bytes()[..])
        }
        if let Some(peer_addr) = peer_addr {
            peer_addr.set(&peer_addr_str.unwrap().into_bytes()[..])
        }
        Ok(self.alloc_fd(FileDesc::Stream(stream)))
    }

    #[inline(always)]
    fn connect_stream(
        &self,
        addr: &[u8],
        local_addr: Option<&mut OutputBuffer>,
        peer_addr: Option<&mut OutputBuffer>,
    ) -> IoResult<Fd> {
        let addr = str::from_utf8(addr).map_err(|_| IoErrorKind::ConnectionRefused)?;
        let mut local_addr_str = local_addr.as_ref().map(|_| String::new());
        let mut peer_addr_str = peer_addr.as_ref().map(|_| String::new());
        if let Some(stream_ext) = self.enclave.usercall_ext.connect_stream(
            &addr,
            local_addr_str.as_mut(),
            peer_addr_str.as_mut(),
        )? {
            if let Some(local_addr) = local_addr {
                local_addr.set(local_addr_str.unwrap().into_bytes());
            }
            if let Some(peer_addr) = peer_addr {
                peer_addr.set(peer_addr_str.unwrap().into_bytes());
            }
            return Ok(self.alloc_fd(FileDesc::Stream(stream_ext)));
        }
        let stream = TcpStream::connect(addr)?;
        if let Some(local_addr) = local_addr {
            match stream.local_addr() {
                Ok(local) => local_addr.set(local.to_string().into_bytes()),
                Err(_) => local_addr.set(&b"error"[..]),
            }
        }
        if let Some(peer_addr) = peer_addr {
            match stream.peer_addr() {
                Ok(peer) => peer_addr.set(peer.to_string().into_bytes()),
                Err(_) => peer_addr.set(&b"error"[..]),
            }
        }
        Ok(self.alloc_fd(FileDesc::Stream(Box::new(stream))))
    }

    #[inline(always)]
    fn launch_thread(&self) -> IoResult<()> {
        let command = self
            .enclave
            .kind
            .as_command()
            .ok_or(IoErrorKind::InvalidInput)?;
        let new_tcs = match self.enclave.threads_queue.pop() {
            Ok(tcs) => tcs,
            Err(a) => {
                return Err(IoErrorKind::WouldBlock.into());
            }
        };

        let ret = self.work_sender.send(Work {
            tcs: RunningTcs {
                pending_events: Default::default(),
                pending_event_set: 0,
                event_queue: new_tcs.event_queue,
                mode: EnclaveEntry::ExecutableNonMain,
            },
            entry: CoEntry::Initial(new_tcs.tcs, 0, 0, 0, 0, 0),
        });
        match ret {
            Ok(()) => Ok(()),
            Err(err) => {
                let y = err.into_inner();
                Err(std::io::Error::new(
                    IoErrorKind::NotConnected,
                    "Work Sender: send error",
                ))
            }
        }
    }

    #[inline(always)]
    fn exit(&mut self, panic: bool) -> EnclaveAbort<bool> {
        self.enclave.abort_all_threads();
        EnclaveAbort::Exit { panic }
    }

    fn check_event_set(set: u64) -> IoResult<u8> {
        const EV_ALL: u64 = EV_USERCALLQ_NOT_FULL | EV_RETURNQ_NOT_EMPTY | EV_UNPARK;
        if (set & !EV_ALL) != 0 {
            return Err(IoErrorKind::InvalidInput.into());
        }

        assert!((EV_ALL | EV_ABORT) <= u8::max_value().into());
        assert!((EV_ALL & EV_ABORT) == 0);
        Ok(set as u8)
    }

    #[inline(always)]
    fn wait(&mut self, event_mask: u64, timeout: u64) -> IoResult<u64> {
        let wait = match timeout {
            WAIT_NO => false,
            WAIT_INDEFINITE => true,
            _ => return Err(IoErrorKind::InvalidInput.into()),
        };

        let event_mask = Self::check_event_set(event_mask)?;

        let mut ret = None;

        if (self.tcs.pending_event_set & event_mask) != 0 {
            if let Some(pos) = self
                .tcs
                .pending_events
                .iter()
                .position(|ev| (ev & event_mask) != 0)
            {
                ret = self.tcs.pending_events.remove(pos);
                self.tcs.pending_event_set = self.tcs.pending_events.iter().fold(0, |m, ev| m | ev);
            }
        }

        if ret.is_none() {
            loop {
                let ev = if wait {
                    // Preventing wait from blocking because the usercalls are synchronous
                    // Once the usercalls are async then this can be reverted

                    match self.tcs.event_queue.try_recv() {
                        Ok(ev) => Ok(ev),
                        Err(mpsc::TryRecvError::Disconnected) => Err(mpsc::RecvError),
                        Err(mpsc::TryRecvError::Empty) => return Ok(event_mask.into()),
                    }
                } else {
                    match self.tcs.event_queue.try_recv() {
                        Ok(ev) => Ok(ev),
                        Err(mpsc::TryRecvError::Disconnected) => Err(mpsc::RecvError),
                        Err(mpsc::TryRecvError::Empty) => break,
                    }
                }
                .expect("TCS event queue disconnected");

                if (ev & (EV_ABORT as u8)) != 0 {
                    // dispatch will make sure this is not returned to enclave
                    return Err(IoErrorKind::Other.into());
                }

                if (ev & event_mask) != 0 {
                    ret = Some(ev);
                    break;
                } else {
                    self.tcs.pending_events.push_back(ev);
                    self.tcs.pending_event_set |= ev;
                }
            }
        }

        if let Some(ret) = ret {
            Ok(ret.into())
        } else {
            Err(IoErrorKind::WouldBlock.into())
        }
    }

    #[inline(always)]
    fn send(&self, event_set: u64, target: Option<Tcs>) -> IoResult<()> {
        let event_set = Self::check_event_set(event_set)?;

        if event_set == 0 {
            return Err(IoErrorKind::InvalidInput.into());
        }

        if let Some(tcs) = target {
            let tcs = TcsAddress(tcs.as_ptr() as _);
            let queue = self
                .enclave
                .event_queues
                .get(&tcs)
                .ok_or(IoErrorKind::InvalidInput)?;
            queue
                .lock()
                .unwrap()
                .send(event_set)
                .expect("TCS event queue disconnected");
        } else {
            for queue in self.enclave.event_queues.values() {
                let _ = queue.lock().unwrap().send(event_set);
            }
        }

        Ok(())
    }

    #[inline(always)]
    fn insecure_time(&mut self) -> u64 {
        let time = time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap();
        (time.subsec_nanos() as u64) + time.as_secs() * 1_000_000_000
    }

    #[inline(always)]
    fn alloc(&self, size: usize, alignment: usize) -> IoResult<*mut u8> {
        unsafe {
            let layout =
                Layout::from_size_align(size, alignment).map_err(|_| IoErrorKind::InvalidInput)?;
            if layout.size() == 0 {
                return Err(IoErrorKind::InvalidInput.into());
            }
            let ptr = System.alloc(layout);
            if ptr.is_null() {
                Err(IoErrorKind::Other.into())
            } else {
                Ok(ptr)
            }
        }
    }

    #[inline(always)]
    fn free(&self, ptr: *mut u8, size: usize, alignment: usize) -> IoResult<()> {
        unsafe {
            let layout =
                Layout::from_size_align(size, alignment).map_err(|_| IoErrorKind::InvalidInput)?;
            if size == 0 {
                return Ok(());
            }
            Ok(System.dealloc(ptr, layout))
        }
    }

    #[inline(always)]
    fn async_queues(
        &self,
        usercall_queue: &mut FifoDescriptor<Usercall>,
        return_queue: &mut FifoDescriptor<Return>,
    ) -> IoResult<()> {
        Err(IoErrorKind::Other.into())
    }
}
