use crate::AsyncUsercallProvider;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

pub(crate) struct AutoPollingProvider {
    provider: AsyncUsercallProvider,
    shutdown: Arc<AtomicBool>,
    join_handle: Option<thread::JoinHandle<()>>,
}

impl AutoPollingProvider {
    pub fn new() -> Self {
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
