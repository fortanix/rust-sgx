#![no_std]

#[macro_use]
extern crate enclave_usercalls;

define_usercalls! {
    fn print(message: *const u8, message_len: usize);
}
