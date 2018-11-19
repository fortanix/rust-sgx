/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use std::io::{self, Read, Write, Result as IoResult, ErrorKind as IoErrorKind};
use std::sync::{Mutex, Arc};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, Sender, Receiver, self};
use std::thread;
use std::cell::RefCell;
use std::result::Result as StdResult;
use std::alloc::{System, GlobalAlloc, Layout};
use std::fmt;
use std::time;
use std::collections::VecDeque;
use std::str;
use std::net::{TcpListener, TcpStream};

use failure;
use fnv::FnvHashMap;

use fortanix_sgx_abi::*;

use sgxs::loader::Tcs as SgxsTcs;

pub mod abi;
mod interface;

use loader::{ErasedTcs, EnclavePanic};
use tcs;
use self::abi::dispatch;
use self::interface::{Handler, OutputBuffer};

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

impl<S: 'static + Send + Sync> SyncStream for S where for<'a> &'a S: Read + Write {
	fn read(&self, buf: &mut [u8]) -> IoResult<usize> {
		Read::read(&mut {self}, buf)
	}

	fn write(&self, buf: & [u8]) -> IoResult<usize> {
		Write::write(&mut {self}, buf)
	}

	fn flush(&self) -> IoResult<()> {
		Write::flush(&mut {self})
	}
}

trait SyncStream: 'static + Send + Sync {
	fn read_alloc(&self, out: &mut OutputBuffer) -> IoResult<()> {
		let mut buf = [0u8; 8192];
		let len = self.read(&mut buf)?;
		out.set(&buf[..len]);
		Ok(())
	}

	fn read(&self, buf: &mut [u8]) -> IoResult<usize>;
	fn write(&self, buf: & [u8]) -> IoResult<usize>;
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
	event_queue: Receiver<u8>
}

struct RunningTcs {
	enclave: Arc<EnclaveState>,
	pending_event_set: u8,
	pending_events: VecDeque<u8>,
	event_queue: Receiver<u8>,
}

pub(crate) struct EnclaveState {
	threads: Mutex<Vec<StoppedTcs>>,
	event_queues: FnvHashMap<TcsAddress, Mutex<Sender<u8>>>,
	fds: Mutex<FnvHashMap<Fd, Arc<FileDesc>>>,
	last_fd: AtomicUsize,
}

impl EnclaveState {
	pub(crate) fn main_entry(main: ErasedTcs, threads: Vec<ErasedTcs>) -> StdResult<(), failure::Error> {
		let mut event_queues = FnvHashMap::with_capacity_and_hasher(threads.len() + 1, Default::default());
		let (main_send, main_recv) = channel();
		event_queues.insert(main.address(), Mutex::new(main_send));

		let mut threads2 = Vec::with_capacity(threads.len());
		for thread in threads {
			let (send, recv) = channel();
			if event_queues.insert(thread.address(), Mutex::new(send)).is_some() {
				panic!("duplicate TCS address: {:p}", thread.address())
			}
			threads2.push(StoppedTcs { tcs: thread, event_queue: recv });
		}

		let mut fds = FnvHashMap::default();
		fds.insert(FD_STDIN, Arc::new(FileDesc::stream(Shared(io::stdin()))));
		fds.insert(FD_STDOUT, Arc::new(FileDesc::stream(Shared(io::stdout()))));
		fds.insert(FD_STDERR, Arc::new(FileDesc::stream(Shared(io::stderr()))));
		let last_fd = AtomicUsize::new(fds.keys().cloned().max().unwrap() as _);

		let enclave = Arc::new(EnclaveState {
			threads: Mutex::new(threads2),
			event_queues,
			fds: Mutex::new(fds),
			last_fd,
		});

		match RunningTcs::entry(enclave, StoppedTcs { tcs: main, event_queue: main_recv }, true) {
			Err(EnclaveAbort::Exit { panic }) => Err(panic.into()),
			Err(EnclaveAbort::IndefiniteWait) => bail!("All enclave threads are waiting indefinitely without possibility of wakeup"),
			Err(EnclaveAbort::InvalidUsercall(n)) => bail!("The enclave performed an invalid usercall 0x{:x}", n),
			Err(EnclaveAbort::MainReturned) => bail!("The enclave returned from the main entrypoint in violation of the specification."),
			Ok(_tcs) => Ok(())
		}
	}

	fn thread_entry(enclave: &Arc<EnclaveState>, tcs: StoppedTcs) -> StoppedTcs {
		RunningTcs::entry(enclave.clone(), tcs, false).unwrap()
	}
}

#[allow(unused_variables)]
impl RunningTcs {
	fn entry(enclave: Arc<EnclaveState>, tcs: StoppedTcs, main: bool) -> StdResult<StoppedTcs, EnclaveAbort<EnclavePanic>> {
		let buf = RefCell::new([0u8; 1024]);

		let mut state = RunningTcs {
			enclave,
			event_queue: tcs.event_queue,
			pending_event_set: 0,
			pending_events: Default::default(),
		};

		let (tcs, result) = {
			let on_usercall = |p1, p2, p3, p4, p5| dispatch(&mut Handler(&mut state), p1, p2, p3, p4, p5);
			tcs::enter(tcs.tcs, on_usercall, 0, 0, 0, 0, 0, Some(&buf))
		};

		let tcs = StoppedTcs { tcs, event_queue: state.event_queue };

		match result {
			Err(EnclaveAbort::Exit { panic: true }) => Err(EnclaveAbort::Exit { panic: EnclavePanic::from(buf.into_inner()) }),
			Err(EnclaveAbort::Exit { panic: false }) => Ok(tcs), // TODO: exit all threads
			Err(EnclaveAbort::IndefiniteWait) => Err(EnclaveAbort::IndefiniteWait), // TODO: join all threads
			Err(EnclaveAbort::InvalidUsercall(n)) => Err(EnclaveAbort::InvalidUsercall(n)),
			Err(EnclaveAbort::MainReturned) => Err(EnclaveAbort::MainReturned),
			Ok(_) if main => Err(EnclaveAbort::MainReturned),
			Ok(_) => Ok(tcs), // TODO: check return value
		}
	}

	fn lookup_fd(&self, fd: Fd) -> IoResult<Arc<FileDesc>> {
		match self.enclave.fds.lock().unwrap().get(&fd) {
			Some(stream) => Ok(stream.clone()),
			None => Err(IoErrorKind::BrokenPipe.into()) // FIXME: Rust normally maps Unix EBADF to `Other`
		}
	}

	fn alloc_fd(&self, stream: FileDesc) -> Fd {
		let fd = (self.enclave.last_fd.fetch_add(1, Ordering::Relaxed).checked_add(1).expect("FD overflow")) as Fd;
		let prev = self.enclave.fds.lock().unwrap().insert(fd, Arc::new(stream));
		debug_assert!(prev.is_none());
		fd
	}

	#[inline(always)]
	fn read(&self, fd: Fd, buf: &mut [u8]) -> IoResult<usize> {
		self.lookup_fd(fd)?.as_stream()?.read(buf)
	}

	#[inline(always)]
	fn read_alloc(&self, fd: Fd, buf: &mut OutputBuffer) -> IoResult<()> {
		self.lookup_fd(fd)?.as_stream()?.read_alloc(buf)
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
	fn accept_stream(&self, fd: Fd, local_addr: Option<&mut OutputBuffer>, peer_addr: Option<&mut OutputBuffer>) -> IoResult<Fd> {
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
	fn connect_stream(&self, addr: &[u8], local_addr: Option<&mut OutputBuffer>, peer_addr: Option<&mut OutputBuffer>) -> IoResult<Fd> {
		let addr = str::from_utf8(addr).map_err(|_| IoErrorKind::ConnectionRefused)?;
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
		Ok(self.alloc_fd(FileDesc::stream(stream)))
	}

	#[inline(always)]
	fn launch_thread(&self) -> IoResult<()> {
		// WouldBlock: see https://github.com/rust-lang/rust/issues/46345
		let new_tcs = self.enclave.threads.lock().unwrap().pop().ok_or(IoErrorKind::WouldBlock)?;
		let (send, recv) = channel();
		let enclave = self.enclave.clone();
		let result = thread::Builder::new().spawn(move || {
			let tcs = recv.recv().unwrap();
			let tcs = EnclaveState::thread_entry(&enclave, tcs);
			enclave.threads.lock().unwrap().push(tcs);
		});
		match result {
			Ok(_join_handle) => {
				send.send(new_tcs).unwrap();
				// TODO: save join handle
				Ok(())
			},
			Err(e) => {
				self.enclave.threads.lock().unwrap().push(new_tcs);
				Err(e)
			}
		}
	}

	fn check_event_set(set: u64) -> IoResult<u8> {
		if (set & !(EV_USERCALLQ_NOT_FULL | EV_RETURNQ_NOT_EMPTY | EV_UNPARK)) != 0 {
			return Err(IoErrorKind::InvalidInput.into())
		}
		
		assert!(EV_USERCALLQ_NOT_FULL | EV_RETURNQ_NOT_EMPTY | EV_UNPARK <= u8::max_value().into());
		Ok(set as u8)
	}

	#[inline(always)]
    fn wait(&mut self, event_mask: u64, timeout: u64) -> IoResult<u64> {
		let wait = match timeout {
			WAIT_NO => false,
			WAIT_INDEFINITE => true,
			_ => return Err(IoErrorKind::InvalidInput.into())
		};

		let event_mask = Self::check_event_set(event_mask)?;

		let mut ret = None;

		if (self.pending_event_set & event_mask) != 0 {
			if let Some(pos) = self.pending_events.iter().position(|ev| (ev & event_mask) != 0) {
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
						Err(mpsc::TryRecvError::Empty) => break
					}
				}.expect("TCS event queue disconnected");

				if (ev & event_mask) != 0 {
					ret = Some(ev);
					break
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
			return Err(IoErrorKind::InvalidInput.into())
		}

		if let Some(tcs) = target {
			let tcs = TcsAddress(tcs.as_ptr() as _);
			let queue = self.enclave.event_queues.get(&tcs).ok_or(IoErrorKind::InvalidInput)?;
			queue.lock().unwrap().send(event_set).expect("TCS event queue disconnected");
		} else {
			for queue in self.enclave.event_queues.values() {
				let _ = queue.lock().unwrap().send(event_set);
			}
		}
		
		Ok(())
	}

	#[inline(always)]
    fn insecure_time(&mut self) -> u64 {
        let time = time::SystemTime::now().duration_since(time::UNIX_EPOCH).unwrap();
        (time.subsec_nanos() as u64) + time.as_secs() * 1_000_000_000
    }

	#[inline(always)]
	fn alloc(&self, size: usize, alignment: usize) -> IoResult<*mut u8> {
		unsafe {
			let layout = Layout::from_size_align(size, alignment).map_err(|_| IoErrorKind::InvalidInput)?;
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
			let layout = Layout::from_size_align(size, alignment).map_err(|_| IoErrorKind::InvalidInput)?;
			Ok(System.dealloc(ptr, layout))
		}
	}

	#[inline(always)]
	fn async_queues(&self, usercall_queue: &mut FifoDescriptor<Usercall>, return_queue: &mut FifoDescriptor<Return>) -> IoResult<()> {
		Err(IoErrorKind::Other.into())
	}
}
