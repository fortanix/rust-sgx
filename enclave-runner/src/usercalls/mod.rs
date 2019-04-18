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
//use term::terminfo::Error::IoError;
use std::error::Error;

const EV_ABORT: u64 = 0b0000_0000_0000_1000;

// //////////////////////////////////////
// // async I/O and enclave scheduling //
// //////////////////////////////////////

// NOTE: The enclave thinks it's doing synchronous I/O. All the async stuff is
// happening in user mode.

static EPOLL_FD: AtomicUsize = AtomicUsize::new(0);
const EPOLL_IGNORE_FD: u64 = !0;
const EPOLL_EVENT_FD: u64 = !0 - 1;

// It's not currently possible to wait on a set of fds *and* a mpsc::Receiver.
// Therefore, we need to wake up epoll() whenever we send something across the
// mpsc channel to avoid deadlocks. We use an eventfd to do this.
static EVENT_FD: AtomicUsize = AtomicUsize::new(0);
static GOT_USR1: AtomicBool = AtomicBool::new(false);


trait CIntError: Sized {
    fn to_errno(self) -> StdResult<Self, i32>;
}

impl CIntError for c_int {
    fn to_errno(self) -> StdResult<Self, i32> {
        if self < 0 {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL))
        } else {
            Ok(self)
        }
    }
}

impl CIntError for libc::ssize_t {
    fn to_errno(self) -> StdResult<Self, i32> {
        if self < 0 {
            Err(std::io::Error::last_os_error().raw_os_error().unwrap_or(libc::EINVAL))
        } else {
            Ok(self)
        }
    }
}

static NEXT_THREAD_ID: AtomicUsize = AtomicUsize::new(0);
thread_local!(static THREAD_ID: usize = NEXT_THREAD_ID.fetch_add(1,Ordering::Relaxed));
//
//lazy_static!{
//    static ref SOCKET_READ_TIMEOUT_SECS: Option<u64> = {
//        match env::var("ENCLAVE_RUNNER_IDLE_TIMEOUT") {
//            Err(env::VarError::NotUnicode(_)) => panic!("ENCLAVE_RUNNER_IDLE_TIMEOUT does not contain a valid UTF-8 string"),
//            Err(env::VarError::NotPresent) => Some(15*60), // 15 minutes (default)
//            Ok(ref s) if s == "off" => None,
//            Ok(ref s) => {
//                let secs = s.parse::<u64>().expect("Failed to parse ENCLAVE_RUNNER_IDLE_TIMEOUT");
//                if secs > i32::max_value() as _ {
//                    panic!("ENCLAVE_RUNNER_IDLE_TIMEOUT too large");
//                }
//                Some(secs)
//            }
//        }
//    };
//}

//#[derive(Default)]
//struct FdWait<'tcs> {
//    mask: c_int,
//    earliest_read_wait: Option<Instant>,
//    pending_usercalls: Vec<Usercall<'tcs>>,
//}
//
//impl<'tcs> FdWait<'tcs> {
//    fn clear(&mut self, parent_count: &mut usize) -> std::vec::Drain<Usercall<'tcs>> {
//        *parent_count -= 1;
//        self.mask = 0;
//        self.earliest_read_wait = None;
//        self.pending_usercalls.drain(..)
//    }
//}
//
//struct FdStore<'tcs> {
//    fds: Vec<FdWait<'tcs>>,
//    count: usize,
//}
//
//impl<'tcs> FdStore<'tcs> {
//    pub fn new() -> Self {
//        FdStore { fds: Vec::new(), count: 0 }
//    }
//
//    /// Returns the epoll event mask for this fd
//    pub fn insert(&mut self, fd: c_int, op: Mode, tcs: Usercall<'tcs>) -> c_int {
//        let fd_usize = fd as usize;
//        if self.fds.len() <= fd_usize {
//            // FIXME: use resize_default or resize_with when stable
//            // https://github.com/rust-lang/rust/issues/41758
//            self.fds.reserve(fd_usize);
//            while self.fds.len() <= fd_usize {
//                self.fds.push(Default::default());
//            }
//        }
//        let entry = &mut self.fds[fd_usize];
//
//        entry.mask |= match op {
//            Mode::Accept => libc::EPOLLIN,
//            Mode::Read => libc::EPOLLIN,
//            Mode::Write => libc::EPOLLOUT,
//            Mode::Close => unreachable!(),
//        };
//
//        if op == Mode::Read && entry.earliest_read_wait.is_none() && ACCEPTED_FDS.get(fd as _) {
//            entry.earliest_read_wait = Some(Instant::now());
//        }
//
//        if entry.pending_usercalls.is_empty() {
//            self.count += 1;
//        }
//        entry.pending_usercalls.push(tcs);
//
//        entry.mask
//    }
//
//    pub fn remove(&mut self, fd: c_int) -> Option<std::vec::Drain<Usercall<'tcs>>> {
//        let count = &mut self.count;
//        self.fds.get_mut(fd as usize).map(|entry| entry.clear(count))
//    }
//
//    pub fn expire_stale<'a>(&'a mut self) -> Box<Iterator<Item=(c_int, std::vec::Drain<Usercall<'tcs>>)> + 'a> {
//        let timeout = if let Some(s) = *SOCKET_READ_TIMEOUT_SECS {
//            Duration::from_secs(s)
//        } else {
//            return Box::new(iter::empty())
//        };
//        let count = &mut self.count;
//        Box::new(self.fds.iter_mut().enumerate()
//            .filter(move |&(_, ref entry)| entry.earliest_read_wait.map_or(false, |then| then.elapsed() > timeout))
//            .map(move |(fd, entry)| (fd as _, entry.clear(count))))
//    }
//
//    pub fn is_empty(&self) -> bool {
//        self.count == 0
//    }
//}

struct ReadOnly<R>(R);
struct WriteOnly<W>(W);

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

#[derive(Debug)]
pub(crate) enum WorkerThreadExit {
    MainReturned,
    NonMainReturned,
    UsercallQueued,
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

struct RunningTcs {
    enclave: Arc<EnclaveState>,
    pending_event_set: u8,
    pending_events: VecDeque<u8>,
    event_queue: Receiver<u8>,
}

enum EnclaveKind {
    Command(Command),
    Library(Library),
}

struct CommandSync {
    threads: Vec<StoppedTcs>,
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

enum UsercallSignal {
    Usercall(RunningTcs,tcs::Usercall<ErasedTcs>, EnclaveEntry),
    HangupSignal,
}
#[derive(Clone, Copy)]
struct Queues<'thread> {
//    start: &'thread crossbeam::queue::SegQueue<StoppedTcs>,
//    work_sender: &'thread crossbeam::channel::Sender<Work>,
    work_receiver: &'thread crossbeam::channel::Receiver<Work>,
    //fd_poll: &'thread mpsc::Sender<Pollcall<'tcs>>,
    io_queue: &'thread mpsc::Sender<UsercallSignal>,
    //io_queue: &'thread mpsc::Sender<(RunningTcs,tcs::Usercall<ErasedTcs>, EnclaveEntry)>,
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
}
enum Work
{
    Stopped(StoppedTcs,EnclaveEntry),
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

    fn epoll_setup() {
        use self::libc::*;
        unsafe {
            let epoll_fd = epoll_create1(EPOLL_CLOEXEC).to_errno().expect("Unable to initialize epoll");
            let event_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK).to_errno().expect("Unable to initialize semaphore");

            let mut ev = epoll_event {
                events: EPOLLIN as _,
                u64: EPOLL_EVENT_FD,
            };
            epoll_ctl(epoll_fd, EPOLL_CTL_ADD, event_fd, &mut ev).to_errno().expect("Error adding event fd to epoll");

            EPOLL_FD.store(epoll_fd as _, Ordering::Relaxed);
            EVENT_FD.store(event_fd as _, Ordering::Relaxed);
        }
    }

    /// Setup signal handling such that `SIGUSR1` is not ignored, but is blocked.
    /// It can't be ignored, as signals with the ignore disposition will never be
    /// pending, even when blocked.
    ///
    /// Only during `epoll_pwait` will `SIGUSR1` be unblocked, in which case it
    /// will be delivered via return error code `EINTR`.
    fn sigusr1_setup() -> libc::sigset_t {
        #[allow(unused)]
        use self::libc::{sigprocmask, sigemptyset, sigaddset, sigdelset, sigaction, SIGUSR1, SIG_BLOCK};

        extern "C" fn set_usr1_flag(_sig: i32) {
            GOT_USR1.store(true, Ordering::SeqCst);
        }

        unsafe {
            let mut sigset = ::std::mem::uninitialized();
            let mut epoll_sigset = ::std::mem::uninitialized();
            sigemptyset(&mut sigset).to_errno().expect("Error calling sigemptyset");

            // ignore USR1 (will be caught by epoll_pwait)
            let action = sigaction { sa_sigaction: set_usr1_flag as _, sa_mask: sigset, sa_flags: 0, sa_restorer: None };
            sigaction(SIGUSR1, &action, std::ptr::null_mut()).to_errno().expect("Error calling sigaction");

            // block USR1
            sigaddset(&mut sigset, SIGUSR1).to_errno().expect("Error calling sigaddset");
            sigprocmask(SIG_BLOCK, &sigset, &mut epoll_sigset).to_errno().expect("Error calling sigprocmask");

            // unblock USR1 during epoll_pwait
            sigdelset(&mut epoll_sigset, SIGUSR1).to_errno().expect("Error calling sigdelset");
            epoll_sigset
        }
    }

    fn new(
        kind: EnclaveKind,
        event_queues: FnvHashMap<TcsAddress, Mutex<Sender<u8>>>,
        usercall_ext: Option<Box<UsercallExtension>>) -> Arc<Self> {
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
        })
    }

    pub(crate) fn main_entry1(
        main: ErasedTcs,
        threads: Vec<ErasedTcs>,
        usercall_ext: Option<Box<UsercallExtension>>) -> StdResult<(), failure::Error>  {
        println!("Size of threads vector, {}",threads.len());
        let mut event_queues =
            FnvHashMap::with_capacity_and_hasher(threads.len() + 1, Default::default());
        let main = Self::event_queue_add_tcs(&mut event_queues, main);
        let threads: Vec<StoppedTcs> = threads
            .into_iter()
            .map(|thread| Self::event_queue_add_tcs(&mut event_queues, thread))
            .collect();


        let (io_queue_send, io_queue_receive) = mpsc::channel();
        let (mut work_sender, work_receiver) = crossbeam::crossbeam_channel::unbounded();
        let start_queue = crossbeam::queue::SegQueue::new();
        start_queue.push(main);
        let threads_copy : Vec<StoppedTcs> = vec![];
        for tcs in threads {
            start_queue.push(tcs);
        }
        //work_queue.push(Work::Start(start_queue.try_pop().expect("at least one thread")));
        if start_queue.is_empty() {
            println!("Start queue is empty");
        }
        work_sender.send(Work::Stopped(start_queue.pop()?, EnclaveEntry::ExecutableMain));
        //EnclaveState::epoll_setup();
        //let epoll_sigset = EnclaveState::sigusr1_setup();
        let mut num_of_threads = num_cpus::get();
        if num_of_threads < 2 {
            num_of_threads = 2;
        }
        if start_queue.is_empty() {
            println!("Start queue is empty2");
        }
        let kind = EnclaveKind::Command(Command {
            data: Mutex::new(CommandSync {
                threads:threads_copy,
                primary_panic_reason: None,
                other_reasons: vec![],
                running_secondary_threads: 0,
                threads_queue: start_queue
            }),
            wait_secondary_threads: Condvar::new(),
        });
        let enclave = EnclaveState::new(kind, event_queues, usercall_ext);

        crossbeam::scope(|scope| {
            // loop for one less than the total number of threads

            // create 1 less than the number of threads

            for _ in 1..num_of_threads {
                //let start_queue = &start_queue;
                //let work_sender = &work_sender;
                let work_receiver = &work_receiver;
                let io_queue_send = io_queue_send.clone();
                let enclave_cloned = enclave.clone();

                scope.spawn(move |_| {
                    THREAD_ID.with(|_| ());
                    let queues = Queues {
//                        start: start_queue,
//                        work_sender,
                        work_receiver,
                        io_queue: &io_queue_send,
                    };
                    // ///////////////////////////
                    // // enclave worker thread //
                    // ///////////////////////////
                    loop {
                        let work = queues.work_receiver.recv();
                        let work = match work {
                            Err(crossbeam::channel::RecvError) => {
                                println!("Received RecvError");
                                break;
                            },
                            Ok(work) => work,
                        };
                        println!("Starting work");
                        //check for error
                        let enclave_cloned = enclave_cloned.clone();
                        let result = match work {
                            Work::Stopped(tcs,mode) => {
                                    RunningTcs::entry_async(enclave_cloned.clone(),tcs, queues, mode)
                            }
                            Work::Running(state, usercall, coresult, mode) => {
                                    RunningTcs::coentry_async(state, usercall, coresult, queues, mode)
                            }
                        };
                        println!("Finished work");
                        if let Ok(WorkerThreadExit::MainReturned) = result {
                            println!("Sending hangup signal");
                            queues.io_queue.send(UsercallSignal::HangupSignal);
                            break;
                        }
                        println!("didnt send hangup signal");

                    }
                });
            }
            // ///////////////////////////////
            // // main syscall polling loop //
            // ///////////////////////////////
            //let mut fds = FdStore::new();
            //let mut fds = Vec
            'outer: loop {
                let maybe_block_recv = |block| if block {
                    println!("Blocking wait on usercall thread");
                    io_queue_receive.recv().ok()
                } else {
                    println!("NonBlocking wait on usercall thread");
                    io_queue_receive.try_recv().ok()
                };

                'inner: while let Some(usercall_signal) = maybe_block_recv(true) {
                    match usercall_signal {
                        UsercallSignal::Usercall(mut state, usercall, mode) => {
                            println!("Got a request");
                            //got a request. make usercall and register with epoll??
                            let mut result;
                            {
                                let mut on_usercall =
                                    |p1, p2, p3, p4, p5| dispatch(&mut Handler(&mut state, &work_sender), p1, p2, p3, p4, p5);
                                let (p1, p2, p3, p4, p5) = usercall.parameters();
                                result = on_usercall(p1, p2, p3, p4, p5);
                            }
                            println!("Usercall done");
                            match result {
                                Ok(ret) => {
//                            let resume_execution  = || {
//                                usercall.coreturn(ret,None)
//                            };
                                    println!("Sending work");
                                    work_sender.send(Work::Running(state, usercall, ret, mode));
                                    println!("Sent work");
                                },
                                Err(err) => {
                                    println!("usercall Error");
                                    /* !!! Do something about the error case*/
                                    match err {
                                        EnclaveAbort::Exit { panic } => {
                                            println!("EnclaveAbort::Exit");
                                            //let error = Err(panic.into());
//                                            assert_eq!(
//                                                (r1,r2),
//                                                (0, 0),
//                                                "Expected enclave thread entrypoint to return zero"
//                                            );
                                            if mode != EnclaveEntry::ExecutableMain {
                                                let cmd = state.enclave.kind.as_command().unwrap();
                                                println!("Getting cmddata from Mutex, send_to_correct_queue");
                                                let mut cmddata = cmd.data.lock().unwrap();
                                                println!("got cmddata from Mutex, send_to_correct_queue");
                                                cmddata.running_secondary_threads -= 1;
                                                if cmddata.running_secondary_threads == 0 {
                                                    cmd.wait_secondary_threads.notify_all();
                                                }
                                                cmddata.threads_queue.push(StoppedTcs {
                                                    tcs: usercall.tcs,
                                                    event_queue: state.event_queue,
                                                });
                                                println!("dropping cmddata, send_to_correct_queue");
                                                //return Ok(WorkerThreadExit::NonMainReturned)
                                            }
                                            else {
//                                                return Ok(WorkerThreadExit::MainReturned)
                                                drop(work_sender);
                                                // !!! do something about the waiting for the threads to give them an exit usercall return
                                                let cmd = enclave.kind.as_command().unwrap();
                                                println!("Getting cmddata from Mutex, usercall loop");
                                                let mut cmddata = cmd.data.lock().unwrap();
                                                println!("got cmddata from Mutex, usercall loop");

                                                cmddata.threads.clear();
                                                //cmddata.threads_queue : crossbeam::queue::SegQueue<StoppedTcs> = crossbeam::queue::SegQueue::new();
                                                enclave.abort_all_threads();
                                                while cmddata.running_secondary_threads > 0 {
                                                    cmddata = cmd.wait_secondary_threads.wait(cmddata).unwrap();
                                                }

                                                println!("Dropping cmddata, usercall loop");
                                                break 'outer;

                                            }

                                        },
                                        EnclaveAbort::IndefiniteWait => {
                                            println!("EnclaveAbort::IndefiniteWait");

//                                            bail!("All enclave threads are waiting indefinitely without possibility of wakeup")
                                        }
                                        EnclaveAbort::InvalidUsercall(n) => {
                                            println!("EnclaveAbort::InvalidUsercall");
//                                            bail!("The enclave performed an invalid usercall 0x{:x}", n)
                                        }
                                        EnclaveAbort::MainReturned => {
                                            println!("EnclaveAbort::InvalidUsercall");
//                                            bail!("The enclave returned from the main entrypoint in violation of the specification.")
                                        },
                                        // Should always be able to return the real exit reason
                                        EnclaveAbort::Secondary => unreachable!(),
                                    }
                                }, //(usercall.tcs, Err(err)),
                            }
                            println!("Finished request");
                        },
                        UsercallSignal::HangupSignal => {
                            println!("Got a hangup");
//                            drop(work_sender);
//                            // !!! do something about the waiting for the threads to give them an exit usercall return
//                            let cmd = enclave.kind.as_command().unwrap();
//                            println!("Getting cmddata from Mutex, usercall loop");
//                            let mut cmddata = cmd.data.lock().unwrap();
//                            println!("got cmddata from Mutex, usercall loop");
//
//                            cmddata.threads.clear();
//                            //cmddata.threads_queue : crossbeam::queue::SegQueue<StoppedTcs> = crossbeam::queue::SegQueue::new();
//                            enclave.abort_all_threads();
//                            while cmddata.running_secondary_threads > 0 {
//                                cmddata = cmd.wait_secondary_threads.wait(cmddata).unwrap();
//                            }
//
//                            println!("Dropping cmddata, usercall loop");
                            break 'outer;
                        }
                    }
                }
            }
        });
        Ok(())
    }


    pub(crate) fn main_entry(
        main: ErasedTcs,
        threads: Vec<ErasedTcs>,
        usercall_ext: Option<Box<UsercallExtension>>) -> StdResult<(), failure::Error>  {
        let mut event_queues =
            FnvHashMap::with_capacity_and_hasher(threads.len() + 1, Default::default());
        let main = Self::event_queue_add_tcs(&mut event_queues, main);

        let threads = threads
            .into_iter()
            .map(|thread| Self::event_queue_add_tcs(&mut event_queues, thread))
            .collect();
        let start_queue = crossbeam::queue::SegQueue::new();
        let kind = EnclaveKind::Command(Command {
            data: Mutex::new(CommandSync {
                threads,
                primary_panic_reason: None,
                other_reasons: vec![],
                running_secondary_threads: 0,
                threads_queue: start_queue,
            }),
            wait_secondary_threads: Condvar::new(),
        });

        let enclave = EnclaveState::new(kind, event_queues, usercall_ext);

        let main_result = RunningTcs::entry(enclave.clone(), main, EnclaveEntry::ExecutableMain);

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

        cmddata.threads.clear();
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

    fn thread_entry(enclave: &Arc<Self>, tcs: StoppedTcs) -> StdResult<StoppedTcs, EnclaveAbort<EnclavePanic>> {
        RunningTcs::entry(enclave.clone(), tcs, EnclaveEntry::ExecutableNonMain)
            .map(|(tcs, result)| {
                assert_eq!(
                    result,
                    (0, 0),
                    "Expected enclave thread entrypoint to return zero"
                );
                tcs
            })
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

        EnclaveState::new(kind, event_queues, usercall_ext)
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
        match RunningTcs::entry(
            enclave.clone(),
            thread,
            EnclaveEntry::Library { p1, p2, p3, p4, p5 },
        ) {
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
            Ok((tcs, result)) => {
                library.thread_sender.lock().unwrap().send(tcs).unwrap();
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

#[derive(PartialEq, Eq)]
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
impl RunningTcs {

    fn send_to_correct_queue (coresult: ThreadResult<ErasedTcs>, state: RunningTcs, queues: Queues, mode: EnclaveEntry)
        -> StdResult<WorkerThreadExit, ()>
    {
        match coresult {
            tcs::CoResult::Return((erased_tcs, r1, r2)) => {
                //(erased_tcs, Ok((r1, r2)));
                assert_eq!(
                    (r1,r2),
                    (0, 0),
                    "Expected enclave thread entrypoint to return zero"
                );
                if mode != EnclaveEntry::ExecutableMain {
                    let cmd = state.enclave.kind.as_command().unwrap();
                    println!("Getting cmddata from Mutex, send_to_correct_queue");
                    let mut cmddata = cmd.data.lock().unwrap();
                    println!("got cmddata from Mutex, send_to_correct_queue");
                    cmddata.running_secondary_threads -= 1;
                    if cmddata.running_secondary_threads == 0 {
                        cmd.wait_secondary_threads.notify_all();
                    }
                    cmddata.threads_queue.push(StoppedTcs {
                        tcs: erased_tcs,
                        event_queue: state.event_queue,
                    });
                    println!("dropping cmddata, send_to_correct_queue");
                    return Ok(WorkerThreadExit::NonMainReturned)
                }
                else {
                    return Ok(WorkerThreadExit::MainReturned)
                }
            },
            tcs::CoResult::Yield(usercall) => {
                queues.io_queue.send(UsercallSignal::Usercall(state, usercall, mode));
                return Ok(WorkerThreadExit::UsercallQueued);
            },
        };

    }

    fn entry_async(
        enclave: Arc<EnclaveState>,
        tcs: StoppedTcs,
        queues: Queues,
        mode: EnclaveEntry
    )
        -> StdResult<WorkerThreadExit, ()>
    {
        let mut state = RunningTcs {
            enclave,
            event_queue: tcs.event_queue,
            pending_event_set: 0,
            pending_events: Default::default(),
        };
        let coresult = {
            let (p1, p2, p3, p4, p5) = match mode {
                EnclaveEntry::Library { p1, p2, p3, p4, p5 } => (p1, p2, p3, p4, p5),
                _ => (0, 0, 0, 0, 0),
            };
            tcs::coenter(tcs.tcs, p1, p2, p3, p4, p5, None)
        };
        Self::send_to_correct_queue(coresult, state, queues, mode)
    }
    fn coentry_async(
        state: RunningTcs,
        completed_usercall: tcs::Usercall<ErasedTcs>,
        completed_usercall_return : (u64,u64),
        queues: Queues,
        mode: EnclaveEntry
    )
        -> StdResult<WorkerThreadExit, ()>
    {
        let coresult =  {
            completed_usercall.coreturn(completed_usercall_return, None)
            //tcs::coenter(tcs.tcs, 0, completed_usercall_result.0, completed_usercall_result.1, 0, 0, None )
        };
        Self::send_to_correct_queue(coresult, state, queues, mode)

    }
    fn entry(
        enclave: Arc<EnclaveState>,
        tcs: StoppedTcs,
        mode: EnclaveEntry,
    ) -> StdResult<(StoppedTcs, (u64, u64)), EnclaveAbort<EnclavePanic>> {
        let buf = RefCell::new([0u8; 1024]);

        let mut state = RunningTcs {
            enclave,
            event_queue: tcs.event_queue,
            pending_event_set: 0,
            pending_events: Default::default(),
        };

        let (tcs, result) = {
            let on_usercall =
                |p1, p2, p3, p4, p5| {Ok((0,0))};//dispatch(&mut Handler(&mut state), p1, p2, p3, p4, p5);
            let (p1, p2, p3, p4, p5) = match mode {
                EnclaveEntry::Library { p1, p2, p3, p4, p5 } => (p1, p2, p3, p4, p5),
                _ => (0, 0, 0, 0, 0),
            };
            tcs::enter(tcs.tcs, on_usercall, p1, p2, p3, p4, p5, Some(&buf))
        };

        let tcs = StoppedTcs {
            tcs,
            event_queue: state.event_queue,
        };

        match result {
            Err(EnclaveAbort::Exit { panic: true }) => {
                trap_attached_debugger(tcs.tcs.address().0 as _);
                Err(EnclaveAbort::Exit {
                    panic: EnclavePanic::from(buf.into_inner()),
                })
            }
            Err(EnclaveAbort::Exit { panic: false }) => Ok((tcs, (0, 0))),
            Err(EnclaveAbort::IndefiniteWait) => Err(EnclaveAbort::IndefiniteWait),
            Err(EnclaveAbort::InvalidUsercall(n)) => Err(EnclaveAbort::InvalidUsercall(n)),
            Err(EnclaveAbort::MainReturned) => Err(EnclaveAbort::MainReturned),
            Err(EnclaveAbort::Secondary) => Err(EnclaveAbort::Secondary),
            Ok(_) if mode == EnclaveEntry::ExecutableMain => Err(EnclaveAbort::MainReturned),
            Ok(result) => Ok((tcs, result)),
        }
    }

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
        if let Some(stream_ext) = self.enclave.usercall_ext
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
    fn launch_thread1(&self, work_sender: &crossbeam::channel::Sender<Work>) -> IoResult<()> {
        let command = self
            .enclave
            .kind
            .as_command()
            .ok_or(IoErrorKind::InvalidInput)?;
        println!("Getting cmddata from Mutex, launch_thread1");
        let mut cmddata = command.data.lock().unwrap();
        println!("got cmddata from matrix");
        if cmddata.threads_queue.is_empty() {
            println!("Threads queue is empty");
        }
        let new_tcs = match cmddata.threads_queue.pop() {
            Ok(tcs) => tcs,
            Err(a) => {return Err(IoErrorKind::InvalidInput.into());},
        };
        println!("Popped tcs from thread_queue");
        let ret = work_sender.send(Work::Stopped(new_tcs, EnclaveEntry::ExecutableNonMain));
        match ret {
            Ok(()) => {
                println!("Dropping cmddata, launch_thread1");
                println!("Added work to queue");
                Ok(())
            },
            Err(err) => {
                println!("Dropping cmddata, launch_thread1");
                println!("Couldn't add to worker queue");
                let y = err.into_inner();
                // do error catching
                Err(std::io::Error::new(IoErrorKind::NotConnected, "Work Sender queue send error"))
            }
        }
    }
    #[inline(always)]
    fn launch_thread(&self) -> IoResult<()> {
        let command = self
            .enclave
            .kind
            .as_command()
            .ok_or(IoErrorKind::InvalidInput)?;

        let mut cmddata = command.data.lock().unwrap();
        // WouldBlock: see https://github.com/rust-lang/rust/issues/46345
        let new_tcs = cmddata.threads.pop().ok_or(IoErrorKind::WouldBlock)?;
        cmddata.running_secondary_threads += 1;

        let (send, recv) = channel();
        let enclave = self.enclave.clone();
        let result = thread::Builder::new().spawn(move || {
            let tcs = recv.recv().unwrap();
            let ret = EnclaveState::thread_entry(&enclave, tcs);

            let cmd = enclave.kind.as_command().unwrap();
            let mut cmddata = cmd.data.lock().unwrap();
            cmddata.running_secondary_threads -= 1;
            if cmddata.running_secondary_threads == 0 {
                cmd.wait_secondary_threads.notify_all();
            }

            match ret {
                Ok(tcs) => {
                    // If the enclave is in the exit-state, threads are no
                    // longer able to be launched
                    if !enclave.exiting.load(Ordering::SeqCst) {
                        cmddata.threads.push(tcs)
                    }
                },
                Err(e @ EnclaveAbort::Exit { .. }) |
                Err(e @ EnclaveAbort::InvalidUsercall(_)) => if cmddata.primary_panic_reason.is_none() {
                    cmddata.primary_panic_reason = Some(e)
                } else {
                    cmddata.other_reasons.push(e)
                },
                Err(EnclaveAbort::Secondary) => {}
                Err(e) => cmddata.other_reasons.push(e),
            }
        });
        match result {
            Ok(_join_handle) => {
                send.send(new_tcs).unwrap();
                Ok(())
            }
            Err(e) => {
                cmddata.running_secondary_threads -= 1;
                // We never released the lock, so if running_secondary_threads
                // is now zero, no other thread has observed it to be non-zero.
                // Therefore, there is no need to notify other waiters.

                cmddata.threads.push(new_tcs);
                Err(e)
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

        if (self.pending_event_set & event_mask) != 0 {
            if let Some(pos) = self
                .pending_events
                .iter()
                .position(|ev| (ev & event_mask) != 0)
            {
                ret = self.pending_events.remove(pos);
                self.pending_event_set = self.pending_events.iter().fold(0, |m, ev| m | ev);
            }
        }

        if ret.is_none() {
            loop {
                let ev = if wait {
                    self.event_queue.recv()
                } else {
                    match self.event_queue.try_recv() {
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
                    self.pending_events.push_back(ev);
                    self.pending_event_set |= ev;
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
