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

#[test]
fn matcher_handle_lifecycle_preserves_matcher_behavior() {
    let handle = unsafe { create(&["10.0.0.42/8", "2001:db8::/32", "invalid network"]) };
    assert!(!handle.is_null());
    assert!(unsafe { ip_matcher_memory_size(handle) } > 0);
    assert_eq!(unsafe { ip_matcher_rejected_count(handle) }, 1);
    assert_eq!(unsafe { has(handle, b"10.255.255.255") }, MATCH);
    assert_eq!(unsafe { has(handle, b"[2001:db8::1]") }, MATCH);
    assert_eq!(unsafe { has(handle, b"::ffff:10.1.2.3") }, MATCH);
    assert_eq!(unsafe { has(handle, b"192.0.2.1") }, NO_MATCH);
    unsafe { ip_matcher_free(handle) };
    unsafe { ip_matcher_free(ptr::null_mut()) };
}
