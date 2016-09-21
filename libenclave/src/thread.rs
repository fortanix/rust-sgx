/*
 * The Rust secure enclave runtime and library.
 *
 * (C) Copyright 2016 Jethro G. Beekman
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Affero General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 */

/// Get the ID for the current thread. The ID is guaranteed to be unique among
/// all currently running threads in the enclave, and it is guaranteed to be
/// constant for the lifetime of the thread. More specifically for SGX, there
/// is a one-to-one correspondence of the ID to the address of the TCS.
pub fn current() -> u64 {
	extern "C" { fn get_thread_id() -> u64; }
	unsafe { get_thread_id() }
}
