use super::*;
use crate::hacks::MakeSend;
use crossbeam_channel as mpmc;
use std::io;
use std::net::{TcpListener, TcpStream};
use std::ops::Deref;
use std::os::fortanix_sgx::io::AsRawFd;
use std::os::fortanix_sgx::usercalls::alloc::User as StdUser;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

struct AutoPollingProvider {
    provider: AsyncUsercallProvider,
    shutdown: Arc<AtomicBool>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl AutoPollingProvider {
    fn new() -> Self {
        let (provider, handler) = AsyncUsercallProvider::new();
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown1 = shutdown.clone();
        let join_handle = Some(thread::spawn(move || loop {
            handler.poll(None);
            if shutdown1.load(Ordering::Relaxed) {
                break;
            }
        }));
        Self {
            provider,
            shutdown,
            join_handle,
        }
    }
}

impl Deref for AutoPollingProvider {
    type Target = AsyncUsercallProvider;

    fn deref(&self) -> &Self::Target {
        &self.provider
    }
}

impl Drop for AutoPollingProvider {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        // send a usercall to ensure thread wakes up
        self.provider.insecure_time(|_| {});
        self.join_handle.take().unwrap().join().unwrap();
    }
}

#[test]
fn get_time_async_raw() {
    fn run(tid: u32, provider: AutoPollingProvider) -> (u32, u32, Duration) {
        let pid = provider.provider_id();
        const N: usize = 500;
        let (tx, rx) = mpmc::bounded(N);
        for _ in 0..N {
            let tx = tx.clone();
            let cb = move |d| {
                let system_time = UNIX_EPOCH + Duration::from_nanos(d);
                tx.send(system_time).unwrap();
            };
            unsafe {
                provider.raw_insecure_time(Some(cb.into()));
            }
        }
        let mut all = Vec::with_capacity(N);
        for _ in 0..N {
            all.push(rx.recv().unwrap());
        }

        assert_eq!(all.len(), N);
        // The results are returned in arbitrary order
        all.sort();
        let t0 = *all.first().unwrap();
        let tn = *all.last().unwrap();
        let total = tn.duration_since(t0).unwrap();
        (tid, pid, total / N as u32)
    }

    println!();
    const THREADS: usize = 4;
    let mut providers = Vec::with_capacity(THREADS);
    for _ in 0..THREADS {
        providers.push(AutoPollingProvider::new());
    }
    let mut handles = Vec::with_capacity(THREADS);
    for (i, provider) in providers.into_iter().enumerate() {
        handles.push(thread::spawn(move || run(i as u32, provider)));
    }
    for h in handles {
        let res = h.join().unwrap();
        println!("[{}/{}] (Tn - T0) / N = {:?}", res.0, res.1, res.2);
    }
}

#[test]
fn raw_alloc_free() {
    let provider = AutoPollingProvider::new();
    let ptr: Arc<AtomicPtr<u8>> = Arc::new(AtomicPtr::new(0 as _));
    let ptr2 = Arc::clone(&ptr);
    const SIZE: usize = 1024;
    const ALIGN: usize = 8;

    let (tx, rx) = mpmc::bounded(1);
    let cb_alloc = move |p: io::Result<*mut u8>| {
        let p = p.unwrap();
        ptr2.store(p, Ordering::Relaxed);
        tx.send(()).unwrap();
    };
    unsafe {
        provider.raw_alloc(SIZE, ALIGN, Some(cb_alloc.into()));
    }
    rx.recv().unwrap();
    let p = ptr.load(Ordering::Relaxed);
    assert!(!p.is_null());

    let (tx, rx) = mpmc::bounded(1);
    let cb_free = move |()| {
        tx.send(()).unwrap();
    };
    unsafe {
        provider.raw_free(p, SIZE, ALIGN, Some(cb_free.into()));
    }
    rx.recv().unwrap();
}

#[test]
fn cancel_accept() {
    let provider = AutoPollingProvider::new();
    let port = 6688;
    let addr = format!("0.0.0.0:{}", port);
    let (tx, rx) = mpmc::bounded(1);
    provider.bind_stream(&addr, move |res| {
        tx.send(res).unwrap();
    });
    let bind_res = rx.recv().unwrap();
    let listener = bind_res.unwrap();
    let fd = listener.as_raw_fd();
    let accept_count = Arc::new(AtomicUsize::new(0));
    let accept_count1 = Arc::clone(&accept_count);
    let (tx, rx) = mpmc::bounded(1);
    let accept = provider.accept_stream(fd, move |res| {
        if let Ok(_) = res {
            accept_count1.fetch_add(1, Ordering::Relaxed);
        }
        tx.send(()).unwrap();
    });
    accept.cancel();
    thread::sleep(Duration::from_millis(10));
    let _ = TcpStream::connect(&addr);
    let _ = rx.recv();
    assert_eq!(accept_count.load(Ordering::Relaxed), 0);
}

#[test]
fn connect() {
    let listener = TcpListener::bind("0.0.0.0:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let provider = AutoPollingProvider::new();
    let (tx, rx) = mpmc::bounded(1);
    provider.connect_stream(&addr, move |res| {
        tx.send(res).unwrap();
    });
    let res = rx.recv().unwrap();
    assert!(res.is_ok());
}

#[test]
fn safe_alloc_free() {
    let provider = AutoPollingProvider::new();

    const LEN: usize = 64 * 1024;
    let (tx, rx) = mpmc::bounded(1);
    provider.alloc_slice::<u8, _>(LEN, move |res| {
        let buf = res.expect("failed to allocate memory");
        tx.send(MakeSend::new(buf)).unwrap();
    });
    let user_buf = rx.recv().unwrap().into_inner();
    assert_eq!(user_buf.len(), LEN);

    let (tx, rx) = mpmc::bounded(1);
    let cb = move || {
        tx.send(()).unwrap();
    };
    provider.free(user_buf, Some(cb));
    rx.recv().unwrap();
}

unsafe impl Send for MakeSend<StdUser<[u8]>> {}

#[test]
fn write_buffer_basic() {
    const LENGTH: usize = 1024;
    let mut write_buffer = WriteBuffer::new(super::alloc_buf(1024));

    let buf = vec![0u8; LENGTH];
    assert_eq!(write_buffer.write(&buf), LENGTH);
    assert_eq!(write_buffer.write(&buf), 0);

    let chunk = write_buffer.consumable_chunk().unwrap();
    write_buffer.consume(chunk, 200);
    assert_eq!(write_buffer.write(&buf), 200);
    assert_eq!(write_buffer.write(&buf), 0);
}

#[test]
#[should_panic]
fn call_consumable_chunk_twice() {
    const LENGTH: usize = 1024;
    let mut write_buffer = WriteBuffer::new(super::alloc_buf(1024));

    let buf = vec![0u8; LENGTH];
    assert_eq!(write_buffer.write(&buf), LENGTH);
    assert_eq!(write_buffer.write(&buf), 0);

    let chunk1 = write_buffer.consumable_chunk().unwrap();
    let _ = write_buffer.consumable_chunk().unwrap();
    drop(chunk1);
}

#[test]
#[should_panic]
fn consume_wrong_buf() {
    const LENGTH: usize = 1024;
    let mut write_buffer = WriteBuffer::new(super::alloc_buf(1024));

    let buf = vec![0u8; LENGTH];
    assert_eq!(write_buffer.write(&buf), LENGTH);
    assert_eq!(write_buffer.write(&buf), 0);

    let unrelated_buf: UserBuf = super::alloc_buf(512).into();
    write_buffer.consume(unrelated_buf, 100);
}

#[test]
fn read_buffer_basic() {
    let mut buf = super::alloc_buf(64);
    const DATA: &'static [u8] = b"hello";
    buf[0..DATA.len()].copy_from_enclave(DATA);

    let mut read_buffer = ReadBuffer::new(buf, DATA.len());
    assert_eq!(read_buffer.len(), DATA.len());
    assert_eq!(read_buffer.remaining_bytes(), DATA.len());
    let mut buf = [0u8; 8];
    assert_eq!(read_buffer.read(&mut buf), DATA.len());
    assert_eq!(read_buffer.remaining_bytes(), 0);
    assert_eq!(&buf, b"hello\0\0\0");
}

#[test]
#[ignore]
fn echo() {
    println!();
    let provider = Arc::new(AutoPollingProvider::new());
    const ADDR: &'static str = "0.0.0.0:7799";
    let (tx, rx) = mpmc::bounded(1);
    provider.bind_stream(ADDR, move |res| {
        tx.send(res).unwrap();
    });
    let bind_res = rx.recv().unwrap();
    let listener = bind_res.unwrap();
    println!("bind done: {:?}", listener);
    let fd = listener.as_raw_fd();
    let cb = KeepAccepting {
        listener,
        provider: Arc::clone(&provider),
    };
    provider.accept_stream(fd, cb);
    thread::sleep(Duration::from_secs(60));
}

struct KeepAccepting {
    listener: TcpListener,
    provider: Arc<AutoPollingProvider>,
}

impl FnOnce<(io::Result<TcpStream>,)> for KeepAccepting {
    type Output = ();

    extern "rust-call" fn call_once(self, args: (io::Result<TcpStream>,)) -> Self::Output {
        let res = args.0;
        println!("accept result: {:?}", res);
        if let Ok(stream) = res {
            let fd = stream.as_raw_fd();
            let cb = Echo {
                stream,
                read: true,
                provider: self.provider.clone(),
            };
            self.provider.read(fd, alloc_buf(Echo::READ_BUF_SIZE), cb);
        }
        let provider = Arc::clone(&self.provider);
        provider.accept_stream(self.listener.as_raw_fd(), self);
    }
}

struct Echo {
    stream: TcpStream,
    read: bool,
    provider: Arc<AutoPollingProvider>,
}

impl Echo {
    const READ_BUF_SIZE: usize = 1024;

    fn close(self) {
        let fd = self.stream.as_raw_fd();
        println!("connection closed, fd = {}", fd);
        self.provider.close(fd, None::<Box<dyn FnOnce() + Send>>);
    }
}

// read callback
impl FnOnce<(io::Result<usize>, User<[u8]>)> for Echo {
    type Output = ();

    extern "rust-call" fn call_once(mut self, args: (io::Result<usize>, User<[u8]>)) -> Self::Output {
        let (res, user) = args;
        assert!(self.read);
        match res {
            Ok(len) if len > 0 => {
                self.read = false;
                let provider = Arc::clone(&self.provider);
                provider.write(self.stream.as_raw_fd(), (user, 0..len).into(), self);
            }
            _ => self.close(),
        }
    }
}

// write callback
impl FnOnce<(io::Result<usize>, UserBuf)> for Echo {
    type Output = ();

    extern "rust-call" fn call_once(mut self, args: (io::Result<usize>, UserBuf)) -> Self::Output {
        let (res, _) = args;
        assert!(!self.read);
        match res {
            Ok(len) if len > 0 => {
                self.read = true;
                let provider = Arc::clone(&self.provider);
                provider.read(self.stream.as_raw_fd(), alloc_buf(Echo::READ_BUF_SIZE), self);
            }
            _ => self.close(),
        }
    }
}
