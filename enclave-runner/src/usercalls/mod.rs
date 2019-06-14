/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

extern crate libc;
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
use std::sync::{Arc, Condvar, Mutex};
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
use self::libc::*;
use self::nix::sys::signal;
use loader::{EnclavePanic, ErasedTcs};
use tcs;
use tcs::{CoResult, ThreadResult};

const EV_ABORT: u64 = 0b0000_0000_0000_1000;

struct ReadOnly<R>(R);
struct WriteOnly<W>(W);

type UsercallSendData = (ThreadResult<ErasedTcs>, RunningTcs, EnclaveEntry, RefCell<[u8;1024]>);
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


trait SyncListener: 'static + Send + Sync {
    fn accept(&self) -> IoResult<(FileDesc, Box<ToString>, Box<ToString>)>;
}

impl SyncListener for TcpListener {
    fn accept(&self) -> IoResult<(FileDesc, Box<ToString>, Box<ToString>)> {
        TcpListener::accept(self).map(|(s, peer)| {
            let local = match s.local_addr() {
                Ok(local) => Box::new(local) as _,
                Err(_) => Box::new("error") as _,
            };
            (FileDesc::stream(s), local, Box::new(peer) as _)
        })
    }
}

enum FileDesc {
    Stream(Box<SyncStream>),
    Listener(Box<SyncListener>),
}

impl FileDesc {
    fn stream<S: SyncStream>(s: S) -> FileDesc {
        FileDesc::Stream(Box::new(s))
    }

    fn listener<L: SyncListener>(l: L) -> FileDesc {
        FileDesc::Listener(Box::new(l))
    }

    fn as_stream(&self) -> IoResult<&SyncStream> {
        if let FileDesc::Stream(ref s) = self {
            Ok(&**s)
        } else {
            Err(IoErrorKind::InvalidInput.into())
        }
    }

    fn as_listener(&self) -> IoResult<&SyncListener> {
        if let FileDesc::Listener(ref l) = self {
            Ok(&**l)
        } else {
            Err(IoErrorKind::InvalidInput.into())
        }
    }
}

#[derive(Debug)]
pub(crate) enum EnclaveAbort<T> {
    Exit { panic: T },
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

struct IOHandlerInput <'a> {
    tcs: &'a mut RunningTcs,
    enclave: Arc<EnclaveState>
}

struct RunningTcs {
    pending_event_set: u8,
    pending_events: VecDeque<u8>,
    event_queue: Receiver<u8>,
}

enum EnclaveKind {
    Command(Command),
    Library(Library),
}

struct CommandSync {
    primary_panic_reason: Option<EnclaveAbort<EnclavePanic>>,
    other_reasons: Vec<EnclaveAbort<EnclavePanic>>,
    running_secondary_threads: usize,
    threads_queue: crossbeam::queue::SegQueue<StoppedTcs>
}

struct Command {
    data: Mutex<CommandSync>,
    // Any lockholder reducing data.running_secondary_threads to 0 must
    // notify_all before releasing the lock
    wait_secondary_threads: Condvar,
}

struct Library {
    threads: Mutex<Receiver<StoppedTcs>>,
    thread_sender: Mutex<Sender<StoppedTcs>>,
}

impl EnclaveKind {
    fn as_command(&self) -> Option<&Command> {
        match self {
            EnclaveKind::Command(c) => Some(c),
            _ => None,
        }
    }

    fn as_library(&self) -> Option<&Library> {
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
    usercall_ext: Box<UsercallExtension>,
    work_sender: Mutex<Option<crossbeam::crossbeam_channel::Sender<Work>>>,
}

enum Work
{
    Stopped(StoppedTcs, EnclaveEntry),
    Running(RunningTcs, tcs::Usercall<ErasedTcs>, (u64,u64), EnclaveEntry),
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
        event_queues: FnvHashMap<TcsAddress, Mutex<Sender<u8>>>,
        usercall_ext: Option<Box<UsercallExtension>>,
        work_sender: Option<crossbeam::crossbeam_channel::Sender<Work>>
    ) -> Arc<Self> {
        let mut fds = FnvHashMap::default();
        fds.insert(FD_STDIN, Arc::new(FileDesc::stream(Shared(io::stdin()))));
        fds.insert(FD_STDOUT, Arc::new(FileDesc::stream(Shared(io::stdout()))));
        fds.insert(FD_STDERR, Arc::new(FileDesc::stream(Shared(io::stderr()))));
        let last_fd = AtomicUsize::new(fds.keys().cloned().max().unwrap() as _);

        let usercall_ext = usercall_ext.unwrap_or_else( || Box::new(UsercallExtensionDefault));

        Arc::new(EnclaveState {
            kind,
            event_queues,
            fds: Mutex::new(fds),
            last_fd,
            exiting: AtomicBool::new(false),
            usercall_ext : usercall_ext,
            work_sender: Mutex::new(work_sender)
        })
    }

    fn create_worker_threads(num_of_threads: usize,
                             work_receiver: crossbeam::crossbeam_channel::Receiver<Work>,
                             io_queue_send: mpsc::Sender<UsercallSendData>,
                             enclave: Arc<EnclaveState>) {
        for _ in 1..num_of_threads {
            let work_receiver = work_receiver.clone();
            let io_queue_send = io_queue_send.clone();
            let enclave = enclave.clone();

            thread::spawn(move || {
                loop {
                    let work = work_receiver.recv();
                    let work = match work {
                        Err(crossbeam::channel::RecvError) => {
                            break;
                        },
                        Ok(work) => work,
                    };
                    let res = match work {
                        Work::Stopped(tcs, mode) => {
                            IOHandlerInput::entry_async(enclave.clone(), tcs, &io_queue_send, mode)
                        },
                        Work::Running(state, usercall, coresult, mode) => {
                            IOHandlerInput::coentry_async(state, usercall, coresult, &io_queue_send, mode)
                        },
                    };
                    if let Err(err) = res {
                        match err.0 {
                            (_, _, EnclaveEntry::ExecutableNonMain, _) => {
                                if let Some(cmd) = enclave.kind.as_command() {
                                    let mut cmddata = cmd.data.lock().unwrap();
                                    cmddata.running_secondary_threads -= 1;
                                    if cmddata.running_secondary_threads == 0 {
                                        cmd.wait_secondary_threads.notify_all();
                                    }
                                }
                                else {
                                    panic!("Could not extract Command from EnclaveState");
                                }
                            },
                            _ => { panic!("IO receiver dropped unexpectedly"); }
                        }
                    }
                }
            });
        }
    }

    fn syscall_loop(io_queue_receive: mpsc::Receiver<UsercallSendData>, enclave: Arc<EnclaveState>) -> StdResult<(u64, u64), EnclaveAbort<EnclavePanic>> {
        let mut main_result;
        'outer: loop {
            let maybe_block_recv = |block| if block {
                io_queue_receive.recv().ok()
            } else {
                io_queue_receive.try_recv().ok()
            };

            'inner: while let Some((coresult, mut state, mode, buf)) = maybe_block_recv(true) {
                let enclave = enclave.clone();
                match coresult {
                    CoResult::Return((tcs,v1, v2)) => {
                        match mode {
                            EnclaveEntry::Library {p1: _, p2: _, p3: _, p4: _, p5: _} => {
                                let lib = enclave.kind.as_library().unwrap().thread_sender.lock().unwrap();
                                if lib.send(StoppedTcs { tcs, event_queue: state.event_queue }).is_err() {
                                    panic!("Work sender couldn't send data to receiver")
                                }
                                main_result = Ok((v1, v2));
                                break 'outer;
                            },
                            EnclaveEntry::ExecutableMain => {
                                main_result = Err(EnclaveAbort::MainReturned);
                                break 'outer;
                            },
                            EnclaveEntry::ExecutableNonMain => {
                                assert_eq!(
                                    (v1, v2),
                                    (0, 0),
                                    "Expected enclave thread entrypoint to return zero"
                                );
                                let cmd = enclave.kind.as_command().unwrap();
                                let mut cmddata = cmd.data.lock().unwrap();
                                cmddata.running_secondary_threads -= 1;
                                if cmddata.running_secondary_threads == 0 {
                                    cmd.wait_secondary_threads.notify_all();
                                }
                                // If the enclave is in the exit-state, threads are no
                                // longer able to be launched
                                if !enclave.exiting.load(Ordering::SeqCst) {
                                    cmddata.threads_queue.push(StoppedTcs {
                                        tcs,
                                        event_queue: state.event_queue,
                                    });
                                }
                            }
                        }
                    },
                    CoResult::Yield(usercall) => {
                        let result;
                        {
                            let mut input = IOHandlerInput { enclave: enclave.clone(), tcs: &mut state };
                            let (p1, p2, p3, p4, p5) = usercall.parameters();
                            result = dispatch(&mut Handler(&mut input), p1, p2, p3, p4, p5);
                        }
                        let mut secondary_return;
                        match result {
                            Ok(ret) => {
                                if enclave.work_sender.lock().unwrap().as_ref().unwrap().send(Work::Running(state, usercall, ret, mode)).is_err() {
                                    panic!("Work sender couldn't send data to receiver")
                                }
                                continue;
                            },
                            Err(EnclaveAbort::Exit { panic: true }) => {
                                trap_attached_debugger(usercall.tcs.address().0 as _);
                                secondary_return = Err(EnclaveAbort::Exit {
                                    panic: EnclavePanic::from(buf.into_inner()),
                                });
                                if let EnclaveEntry::Library {p1: _, p2: _, p3: _, p4: _, p5: _} = mode {
                                    main_result = secondary_return;
                                    break 'outer;
                                }
                            },
                            Err(EnclaveAbort::Exit { panic: false }) => {
                                match mode {
                                    EnclaveEntry::ExecutableNonMain => {
                                        let cmd = enclave.kind.as_command().unwrap();
                                        let mut cmddata = cmd.data.lock().unwrap();
                                        cmddata.running_secondary_threads -= 1;
                                        if cmddata.running_secondary_threads == 0 {
                                            cmd.wait_secondary_threads.notify_all();
                                        }
                                        // If the enclave is in the exit-state, threads are no
                                        // longer able to be launched
                                        if !enclave.exiting.load(Ordering::SeqCst) {
                                            cmddata.threads_queue.push(StoppedTcs {
                                                tcs: usercall.tcs,
                                                event_queue: state.event_queue,
                                            });
                                        }
                                        secondary_return = Ok((0,0));
                                    }
                                    EnclaveEntry::ExecutableMain => {
                                        secondary_return = Ok((0,0));
                                    }
                                    EnclaveEntry::Library {p1: _, p2: _, p3: _, p4: _, p5: _} => {
                                        let lib = enclave.kind.as_library().unwrap()
                                            .thread_sender.lock().unwrap();
                                        if lib.send(
                                            StoppedTcs {
                                                tcs: usercall.tcs,
                                                event_queue: state.event_queue
                                            }).is_err()
                                        {
                                            panic!("Work sender couldn't send data to receiver")
                                        }
                                        main_result =  Ok((0,0));
                                        break 'outer;
                                    }
                                }
                            },
                            Err(EnclaveAbort::IndefiniteWait) => secondary_return = Err(EnclaveAbort::IndefiniteWait),
                            Err(EnclaveAbort::InvalidUsercall(n)) => secondary_return = Err(EnclaveAbort::InvalidUsercall(n)),
                            Err(EnclaveAbort::MainReturned) => secondary_return = Err(EnclaveAbort::MainReturned),
                            Err(EnclaveAbort::Secondary) => secondary_return = Err(EnclaveAbort::Secondary),
                        }
                        if mode == EnclaveEntry::ExecutableNonMain {
                            match secondary_return {
                                Ok(_) => {},
                                Err(e @ EnclaveAbort::Exit { .. }) |
                                Err(e @ EnclaveAbort::InvalidUsercall(_)) => {
                                    let cmd = enclave.kind.as_command().unwrap();
                                    let mut cmddata = cmd.data.lock().unwrap();

                                    if cmddata.primary_panic_reason.is_none() {
                                        cmddata.primary_panic_reason = Some(e)
                                    } else {
                                        cmddata.other_reasons.push(e)
                                    }
                                },
                                Err(EnclaveAbort::Secondary) => {}
                                Err(e) => {
                                    let cmd = enclave.kind.as_command().unwrap();
                                    let mut cmddata = cmd.data.lock().unwrap();
                                    cmddata.other_reasons.push(e)
                                },
                            }
                        }
                        else {
                            main_result = secondary_return;
                            break 'outer;
                        }
                    }
                }
            }
        }
        let worksender = enclave.work_sender.lock().unwrap().take();
        if let Some(ws) = worksender {
            drop(ws);
        }
        drop(io_queue_receive);
        return main_result;
    }

    pub(crate) fn main_entry(
        main: ErasedTcs,
        threads: Vec<ErasedTcs>,
        usercall_ext: Option<Box<UsercallExtension>>) -> StdResult<(), failure::Error>  {
        let mut event_queues =
            FnvHashMap::with_capacity_and_hasher(threads.len() + 1, Default::default());
        let main = Self::event_queue_add_tcs(&mut event_queues, main);
        let threads: Vec<StoppedTcs> = threads
            .into_iter()
            .map(|thread| Self::event_queue_add_tcs(&mut event_queues, thread))
            .collect();


        let (io_queue_send, io_queue_receive) = mpsc::channel();
        let (work_sender, work_receiver) = crossbeam::crossbeam_channel::unbounded();
        let start_queue = crossbeam::queue::SegQueue::new();
        for tcs in threads {
            start_queue.push(tcs);
        }

        if work_sender.send(Work::Stopped(main, EnclaveEntry::ExecutableMain)).is_err()
        {
            panic!("Work sender couldn't send data to receiver")
        }

        let mut num_of_threads = num_cpus::get();
        if num_of_threads < 2 {
            num_of_threads = 2;
        }
        let kind = EnclaveKind::Command(Command {
            data: Mutex::new(CommandSync {
                primary_panic_reason: None,
                other_reasons: vec![],
                running_secondary_threads: 0,
                threads_queue: start_queue
            }),
            wait_secondary_threads: Condvar::new(),
        });
        let enclave = EnclaveState::new(kind, event_queues, usercall_ext, Some(work_sender));

        // loop for one less than the total number of threads
        // create 1 less than the number of threads
        EnclaveState::create_worker_threads( num_of_threads, work_receiver,io_queue_send, enclave.clone());
        // main syscall polling loop
        let mut main_result = EnclaveState::syscall_loop(io_queue_receive, enclave.clone());
        let main_panicking = match main_result {
            Err(EnclaveAbort::MainReturned) |
            Err(EnclaveAbort::InvalidUsercall(_)) |
            Err(EnclaveAbort::Exit { .. }) => true,
            Err(EnclaveAbort::IndefiniteWait) |
            Err(EnclaveAbort::Secondary) |
            Ok(_) => false,
        };
        let cmd = enclave.kind.as_command().unwrap();
        let mut cmddata = cmd.data.lock().unwrap();
        //clear the threads_queue
        cmddata.threads_queue  = crossbeam::queue::SegQueue::new();
        enclave.abort_all_threads();
        while cmddata.running_secondary_threads > 0 {
            cmddata = cmd.wait_secondary_threads.wait(cmddata).unwrap();
        }

        let main_result = match (main_panicking, cmddata.primary_panic_reason.take()) {
            (false, Some(reason)) => Err(reason),
            // TODO: interpret other_reasons
            _ => main_result
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

    pub(crate) fn library(threads: Vec<ErasedTcs>,
                          usercall_ext: Option<Box<UsercallExtension>>) -> Arc<Self> {
        let mut event_queues =
            FnvHashMap::with_capacity_and_hasher(threads.len(), Default::default());
        let (send, recv) = channel();

        for thread in threads {
            send.send(Self::event_queue_add_tcs(&mut event_queues, thread))
                .unwrap();
        }

        let kind = EnclaveKind::Library(Library {
            threads: Mutex::new(recv),
            thread_sender: Mutex::new(send),
        });

        EnclaveState::new(kind, event_queues, usercall_ext, None)
    }

    pub(crate) fn library_entry(
        enclave: &Arc<Self>,
        p1: u64,
        p2: u64,
        p3: u64,
        p4: u64,
        p5: u64,
    ) -> StdResult<(u64, u64), failure::Error> {
        // There is no other way than `Self::library` to get an `Arc<Self>`
        let library = enclave.kind.as_library().unwrap();
        let thread = library.threads.lock().unwrap().recv().unwrap();

        let (io_queue_send, io_queue_receive) = mpsc::channel();
        let (work_sender, work_receiver) = crossbeam::crossbeam_channel::unbounded();
        if work_sender.send(Work::Stopped(thread, EnclaveEntry::Library {p1, p2, p3, p4, p5})).is_err()
        {
            panic!("Error sending data via the work sender");
        }
        enclave.work_sender.lock().unwrap().replace(work_sender);
        // As currently we are not supporting spawning threads let the number of threads be 2
        // one for usercall handling the other for actually runnign
        let num_of_threads = 2;

        EnclaveState::create_worker_threads(num_of_threads, work_receiver,io_queue_send, enclave.clone());
        // main syscall polling loop
        let library_result = EnclaveState::syscall_loop(io_queue_receive, enclave.clone());

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
            Ok(result) => {
                Ok(result)
            }
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

#[derive(Debug, PartialEq, Eq)]
enum EnclaveEntry {
    ExecutableMain,
    ExecutableNonMain,
    Library {
        p1: u64,
        p2: u64,
        p3: u64,
        p4: u64,
        p5: u64,
    },
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

pub trait UsercallExtension : 'static + Send + Sync + std::fmt::Debug {
    /// Override the connection target for connect calls by the enclave. The runner should determine the service that the enclave is trying to connect to by looking at addr.
    /// If `connect_stream` returns None, the default implementation of [`connect_stream`](../../fortanix_sgx_abi/struct.Usercalls.html#method.connect_stream) is used.
    /// The enclave may optionally request the local or peer addresses
    /// be returned in `local_addr` or `peer_addr`, respectively. On success,
    /// if `local_addr` and/or `peer_addr` is not None,
    /// user-space can fill in the strings as appropriate.
    ///
    /// The enclave must not make any security decisions based on the local or
    /// peer address received.
    #[allow(unused)]
    fn connect_stream(
        &self,
        addr: &str,
        local_addr: Option<&mut String>,
        peer_addr: Option<&mut String>,
    ) -> IoResult<Option<Box<SyncStream>>> {
        Ok(None)
    }
}

impl<T: UsercallExtension> From<T> for Box<UsercallExtension> {
    fn from(value : T) -> Box<UsercallExtension> {
        Box::new(value)
    }
}

#[derive(Debug)]
struct UsercallExtensionDefault;
impl UsercallExtension for UsercallExtensionDefault{
    fn connect_stream(
        &self,
        _addr: &str,
        _local_addr: Option<&mut String>,
        _peer_addr: Option<&mut String>,
    ) -> IoResult<Option<Box<SyncStream>>> {
        Ok(None)
    }
}

#[allow(unused_variables)]
impl<'a> IOHandlerInput<'a> {

    fn entry_async(
        enclave: Arc<EnclaveState>,
        tcs: StoppedTcs,
        io_send_queue: &mpsc::Sender<UsercallSendData>,
        mode: EnclaveEntry
    )-> StdResult<(), mpsc::SendError<UsercallSendData>>
    {
        let buf = RefCell::new([0u8; 1024]);

        let state = RunningTcs {
            event_queue: tcs.event_queue,
            pending_event_set: 0,
            pending_events: Default::default(),
        };

        let coresult = {
            let (p1, p2, p3, p4, p5) = match mode {
                EnclaveEntry::Library { p1, p2, p3, p4, p5 } => (p1, p2, p3, p4, p5),
                _ => (0, 0, 0, 0, 0),
            };
            tcs::coenter(tcs.tcs, p1, p2, p3, p4, p5, Some(&buf))
        };

        io_send_queue.send((coresult, state, mode, buf))
    }

    fn coentry_async(
        state: RunningTcs,
        completed_usercall: tcs::Usercall<ErasedTcs>,
        completed_usercall_return : (u64,u64),
        io_send_queue: &mpsc::Sender<UsercallSendData>,
        mode: EnclaveEntry
    ) -> StdResult<(), mpsc::SendError<UsercallSendData>>
    {
        let buf = RefCell::new([0u8; 1024]);

        let coresult =  {
            completed_usercall.coreturn(completed_usercall_return, Some(&buf))
        };
        io_send_queue.send((coresult, state, mode, buf))
    }

    fn lookup_fd(&self, fd: Fd) -> IoResult<Arc<FileDesc>> {
        match self.enclave.as_ref().fds.lock().unwrap().get(&fd) {
            Some(stream) => Ok(stream.clone()),
            None => Err(IoErrorKind::BrokenPipe.into()), // FIXME: Rust normally maps Unix EBADF to `Other`
        }
    }

    fn alloc_fd(&self, stream: FileDesc) -> Fd {
        let fd = (self
            .enclave
            .as_ref()
            .last_fd
            .fetch_add(1, Ordering::Relaxed)
            .checked_add(1)
            .expect("FD overflow")) as Fd;
        let prev = self
            .enclave
            .as_ref()
            .fds
            .lock()
            .unwrap()
            .insert(fd, Arc::new(stream));
        debug_assert!(prev.is_none());
        fd
    }

    #[inline(always)]
    fn is_exiting(&self) -> bool {
        self.enclave.as_ref().exiting.load(Ordering::SeqCst)
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
        self.enclave.as_ref().fds.lock().unwrap().remove(&fd);
    }

    #[inline(always)]
    fn bind_stream(&self, addr: &[u8], local_addr: Option<&mut OutputBuffer>) -> IoResult<Fd> {
        let addr = str::from_utf8(addr).map_err(|_| IoErrorKind::ConnectionRefused)?;
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
        let (stream, local, peer) = self.lookup_fd(fd)?.as_listener()?.accept()?;
        if let Some(local_addr) = local_addr {
            local_addr.set(local.to_string().into_bytes())
        }
        if let Some(peer_addr) = peer_addr {
            peer_addr.set(peer.to_string().into_bytes())
        }
        Ok(self.alloc_fd(stream))
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
        if let Some(stream_ext) = self.enclave.as_ref().usercall_ext
            .connect_stream(&addr, local_addr_str.as_mut(), peer_addr_str.as_mut())? {
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
        let enclave = self.enclave.as_ref();
        let command = enclave
            .kind
            .as_command()
            .ok_or(IoErrorKind::InvalidInput)?;
        let mut cmddata = command.data.lock().unwrap();
        cmddata.running_secondary_threads += 1;

        let new_tcs = match cmddata.threads_queue.pop() {
            Ok(tcs) => tcs,
            Err(a) => {return Err(IoErrorKind::WouldBlock.into());},
        };

        let ret = enclave.work_sender.lock().unwrap().as_ref().unwrap()
            .send(Work::Stopped(new_tcs, EnclaveEntry::ExecutableNonMain));
        match ret {
            Ok(()) => {
                Ok(())
            },
            Err(err) => {
                let y = err.into_inner();
                Err(std::io::Error::new(IoErrorKind::NotConnected, "Work Sender: send error"))
            }
        }
    }

    #[inline(always)]
    fn exit(&mut self, panic: bool) -> EnclaveAbort<bool> {
        self.enclave.as_ref().abort_all_threads();
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
                .as_ref()
                .event_queues
                .get(&tcs)
                .ok_or(IoErrorKind::InvalidInput)?;
            queue
                .lock()
                .unwrap()
                .send(event_set)
                .expect("TCS event queue disconnected");
        } else {
            for queue in self.enclave.as_ref().event_queues.values() {
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
                return Ok(())
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
