use crate::queues::*;
use crate::CancelHandle;
use crossbeam_channel as mpmc;
use ipc_queue::Identified;
use std::os::fortanix_sgx::usercalls::raw::{Cancel, Return, Usercall};
use std::sync::atomic::{AtomicU32, Ordering};

pub(crate) struct ProviderCore {
    provider_id: u32,
    next_id: AtomicU32,
}

impl ProviderCore {
    pub fn new(return_tx: Option<mpmc::Sender<Identified<Return>>>) -> ProviderCore {
        let provider_id = PROVIDERS.new_provider(return_tx);
        ProviderCore {
            provider_id,
            next_id: AtomicU32::new(1),
        }
    }

    #[cfg(test)]
    pub fn provider_id(&self) -> u32 {
        self.provider_id
    }

    fn next_id(&self) -> u32 {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        match id {
            0 => self.next_id(),
            _ => id,
        }
    }

    pub fn assign_id(&self, usercall: Usercall) -> Identified<Usercall> {
        let id = self.next_id();
        Identified {
            id: ((self.provider_id as u64) << 32) | id as u64,
            data: usercall,
        }
    }

    pub fn send_usercall(&self, usercall: Identified<Usercall>) -> CancelHandle {
        assert!(usercall.id != 0);
        let cancel = Identified {
            id: usercall.id,
            data: Cancel,
        };
        PROVIDERS
            .usercall_sender()
            .send(usercall)
            .expect("failed to send async usercall");
        CancelHandle::new(cancel)
    }

    // returns the number of usercalls successfully sent.
    pub fn try_send_multiple_usercalls(&self, usercalls: &[Identified<Usercall>]) -> usize {
        PROVIDERS.usercall_sender().try_send_multiple(usercalls).unwrap_or(0)
    }
}

impl Drop for ProviderCore {
    fn drop(&mut self) {
        PROVIDERS.remove_provider(self.provider_id);
    }
}

pub trait ProviderId {
    fn provider_id(&self) -> u32;
}

impl<T> ProviderId for Identified<T> {
    fn provider_id(&self) -> u32 {
        (self.id >> 32) as u32
    }
}
