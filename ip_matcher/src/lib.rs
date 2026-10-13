#![cfg_attr(not(test), no_std)]

extern crate alloc;
#[cfg(all(feature = "std", not(test)))]
extern crate std;

mod matcher;
#[cfg(test)]
mod matcher_test;

pub mod ffi;
#[cfg(test)]
mod ffi_test;

pub use matcher::IpMatcher;
