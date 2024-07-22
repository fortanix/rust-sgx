use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt::{Write, Error as FmtError};
use std::result::Result as StdResult;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::usercalls::*;

use fortanix_sgx_abi::*;

use lazy_static::lazy_static;

lazy_static! {
    static ref USERCALL_COUNTERS: [AtomicUsize; 17] = [
        AtomicUsize::default(),
        AtomicUsize::default(), AtomicUsize::default(), AtomicUsize::default(), AtomicUsize::default(),
        AtomicUsize::default(), AtomicUsize::default(), AtomicUsize::default(), AtomicUsize::default(),
        AtomicUsize::default(), AtomicUsize::default(), AtomicUsize::default(), AtomicUsize::default(),
        AtomicUsize::default(), AtomicUsize::default(), AtomicUsize::default(), AtomicUsize::default(),
    ];
    static ref TCS_MAPPINGS: Arc<Mutex<HashMap<usize, TcsStats>>> = Arc::new(Mutex::new(HashMap::new()));
}

#[derive(Clone, Default, Debug)]
pub struct TcsStats {
    // Each index corresponds to that usercall number
    sync_calls: [usize; 17],
    // WAIT_NO, WAIT_INDEFINITE, other
    // There are 16 because there are 4 possible events to wait for
    waits: [(usize, usize, usize); 16],
    // targeted, not targeted
    sends: [usize; 16],
}

pub struct RunnerStats {
    pub sync_calls: HashMap<usize, TcsStats>,
    pub async_calls: [usize; 17],
}

impl RunnerStats {
    /// The total number of sync usercalls that have been handled as of this snapshot
    pub fn total_sync_calls(&self) -> usize {
        self.sync_calls.iter()
            .map(|(_, stats)| stats.sync_calls.iter().sum::<usize>())
            .sum()
    }

    /// The total number of async usercalls that have been handled as of this snapshot
    pub fn total_async_calls(&self) -> usize {
        self.async_calls.iter().sum::<usize>()
    }

    /// The total number of usercalls that have been handled as of this snapshot
    pub fn total_calls(&self) -> usize {
        self.total_sync_calls() + self.total_async_calls()
    }

    // A "stock" formatting for this information
    pub fn pretty_format(&self) -> StdResult<String, FmtError> {
        let mut out = String::new();
        let mut counts = USERCALL_COUNTERS.iter()
            .enumerate()
            .map(|(i, counter)| (i, counter.load(Ordering::Relaxed)))
            .filter(|(_, counter)| *counter > 0)
            .map(|(i, counter)| format!("{:?}: {}", abi::UsercallList::from_u64(i as _), counter))
            .collect::<Vec<_>>()
            .join(", ");

        if counts.is_empty() {
            counts = "None".to_owned();
        }

        writeln!(out, "Async usercall counts: {}", counts)?;
        writeln!(out, "Sync usercall count mappings:")?;
        for (addr, stats) in TCS_MAPPINGS.lock().map_err(|_| FmtError)?.iter() {
            if stats.should_print() {
                writeln!(out, "Address: 0x{:0>16x}", addr)?;
                write!(out, "{}", stats.format()?)?;
            }
        }

        Ok(out)
    }
}

fn mask_to_str(ev: usize) -> String {
    let mut events = vec!();
    let ev = ev as u64;
    if ev & EV_CANCELQ_NOT_FULL != 0 {
        events.push("CANCELQ_NOT_FULL");
    }
    if ev & EV_RETURNQ_NOT_EMPTY != 0 {
        events.push("RETURNQ_NOT_EMPTY");
    }
    if ev & EV_USERCALLQ_NOT_FULL != 0 {
        events.push("USERCALLQ_NOT_FULL");
    }
    if ev & EV_UNPARK != 0 {
        events.push("UNPARK");
    }
    if events.is_empty() {
        events.push("NONE");
    }
    events.join(" | ")
}

pub(crate) fn record_usercall(
    tcs_address: Option<TcsAddress>,
    p1: u64,
    p2: u64,
    p3: u64
) {
    // Map sync usercalls to the TCS that made them
    if let Some(tcs_address) = tcs_address {
        let mut mappings = TCS_MAPPINGS.lock().expect("poisoned mutex");
        let entry = mappings.entry(tcs_address.0).or_default();
        // type
        entry.sync_calls[p1 as usize] += 1;
        if p1 == 11 {
            // waits
            let mask = &mut entry.waits[p2 as usize];
            match p3 {
                WAIT_NO => mask.0 += 1,
                WAIT_INDEFINITE => mask.1 += 1,
                _ => mask.2 += 1,
            }
        } else if p1 == 12 {
            // sends
            entry.sends[p2 as usize] += 1; // event mask
        }
    } else {
        // For async calls where we don't know the TCS, just store aggregates
        USERCALL_COUNTERS[p1 as usize].fetch_add(1, Ordering::Relaxed);
    }
}

impl TcsStats {
    fn should_print(&self) -> bool {
        self.sync_calls.iter().sum::<usize>() > 10
    }

    pub fn format(&self) -> StdResult<String, FmtError> {
        let mut out = String::new();
        writeln!(out,
            "    Sync Totals: {}",
            self.sync_calls.iter()
                .enumerate()
                .filter(|(_, cnt)| **cnt > 0)
                .map(|(idx, cnt)| {
                    format!("{:?}: {}", abi::UsercallList::from_u64(idx as u64), cnt)
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        writeln!(out,
            "    Wait Totals: {}",
            self.waits.iter()
                .enumerate()
                .filter(|(_, (a, b, c))| a + b + c > 0)
                .map(|(idx, cnt)| {
                    let mut out = format!("{}: ", mask_to_str(idx));
                    let mut masks = Vec::new();
                    if cnt.0 > 0 {
                        masks.push(format!("WAIT_NO: {}", cnt.0))
                    }
                    if cnt.1 > 0 {
                        masks.push(format!("WAIT_INDEFINITE: {}", cnt.1));
                    }
                    if cnt.2 > 0 {
                        masks.push(format!("OTHER: {}", cnt.2));
                    }
                    out.push_str(&masks.join(", "));
                    out
                })
                .collect::<Vec<_>>()
                .join("\n                 ")
        )?;
        writeln!(out,
            "    Send Totals: {}",
            self.sends.iter()
                .enumerate()
                .filter(|(_, cnt)| **cnt > 0)
                .map(|(idx, cnt)| {
                    format!("{}: {}", mask_to_str(idx), cnt)
                })
                .collect::<Vec<_>>()
                .join(", ")
        )?;
        Ok(out)
    }
}

pub fn get_stats() -> RunnerStats {
    let async_calls: [usize; 17] = USERCALL_COUNTERS.iter()
        .map(|c| c.load(Ordering::Relaxed))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();

    assert!(async_calls.len() == 17);

    let sync_calls = {
        TCS_MAPPINGS.lock().expect("poison error").clone()
    };

    RunnerStats {
        sync_calls,
        async_calls,
    }
}
