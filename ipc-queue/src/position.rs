/* Copyright (c) Fortanix, Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use super::*;
use std::sync::atomic::Ordering;

impl<T> PositionMonitor<T> {
    pub fn read_position(&self) -> ReadPosition {
        let current = self.fifo.current_offsets(Ordering::Relaxed);
        let read_epoch = self.read_epoch.load(Ordering::Relaxed);
        ReadPosition(((read_epoch as u64) << 32) | (current.read_offset() as u64))
    }

    pub fn write_position(&self) -> WritePosition {
        let current = self.fifo.current_offsets(Ordering::Relaxed);
        let mut write_epoch = self.read_epoch.load(Ordering::Relaxed);
        if current.read_high_bit() != current.write_high_bit() {
            write_epoch += 1;
        }
        WritePosition(((write_epoch as u64) << 32) | (current.write_offset() as u64))
    }
}

impl<T> Clone for PositionMonitor<T> {
    fn clone(&self) -> Self {
        Self {
            read_epoch: self.read_epoch.clone(),
            fifo: self.fifo.clone(),
        }
    }
}

impl ReadPosition {
    /// A `WritePosition` can be compared to a `ReadPosition` **correctly** if
    /// at most 2³¹ writes have occured since the write position was recorded.
    pub fn is_past(&self, write: &WritePosition) -> bool {
        let (read, write) = (self.0, write.0);
        let hr = read & (1 << 63);
        let hw = write & (1 << 63);
        if hr == hw {
            return read > write;
        }
        true
    }
}
