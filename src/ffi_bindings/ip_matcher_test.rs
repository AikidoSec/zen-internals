use super::ip_matcher::{
    ip_matcher_create, ip_matcher_free, ip_matcher_has, ip_matcher_memory_size,
    ip_matcher_rejected_count, IpMatcherHandle,
};
use std::os::raw::c_int;
use std::ptr;
use std::ptr::NonNull;

const NO_MATCH: c_int = 0;
const MATCH: c_int = 1;
const ERROR: c_int = 2;

unsafe fn create(networks: &[&str]) -> *mut IpMatcherHandle {
    let networks = networks.join("\n");
    unsafe { ip_matcher_create(networks.as_ptr(), networks.len()) }
}

unsafe fn has(handle: *const IpMatcherHandle, value: &[u8]) -> c_int {
    unsafe { ip_matcher_has(handle, value.as_ptr(), value.len()) }
}
