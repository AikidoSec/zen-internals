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

#[test]
fn rejected_count_is_zero_when_every_network_is_valid() {
    let handle = unsafe { create(&["10.0.0.0/8", "2001:db8::/32"]) };
    assert!(!handle.is_null());
    assert_eq!(unsafe { ip_matcher_rejected_count(handle) }, 0);
    unsafe { ip_matcher_free(handle) };

    let empty = unsafe { ip_matcher_create(ptr::null(), 0) };
    assert!(!empty.is_null());
    assert_eq!(unsafe { ip_matcher_rejected_count(empty) }, 0);
    unsafe { ip_matcher_free(empty) };
}

#[test]
fn creation_rejects_structural_errors_and_limits() {
    assert_eq!(unsafe { ip_matcher_memory_size(ptr::null()) }, 0);
    assert_eq!(unsafe { ip_matcher_rejected_count(ptr::null()) }, 0);
    assert!(unsafe { ip_matcher_create(ptr::null(), 1) }.is_null());

    let invalid_utf8 = [0xc3, 0x28];
    assert!(unsafe { ip_matcher_create(invalid_utf8.as_ptr(), invalid_utf8.len()) }.is_null());

    let oversized = NonNull::<u8>::dangling().as_ptr();
    assert!(unsafe { ip_matcher_create(oversized, 64 * 1024 * 1024 + 1) }.is_null());

    let at_limit = unsafe { create(&vec!["10.0.0.1"; 1_000_000]) };
    assert!(!at_limit.is_null());
    unsafe { ip_matcher_free(at_limit) };
    assert!(unsafe { create(&vec!["10.0.0.1"; 1_000_001]) }.is_null());
}

#[test]
fn networks_are_separated_by_newlines() {
    let empty = unsafe { create(&[]) };
    assert!(!empty.is_null());
    assert_eq!(unsafe { ip_matcher_rejected_count(empty) }, 0);
    assert_eq!(unsafe { has(empty, b"10.0.0.1") }, NO_MATCH);
    unsafe { ip_matcher_free(empty) };

    // A trailing newline adds an empty entry, which is rejected.
    let trailing = unsafe { ip_matcher_create(b"10.0.0.0/8\n".as_ptr(), 11) };
    assert!(!trailing.is_null());
    assert_eq!(unsafe { ip_matcher_rejected_count(trailing) }, 1);
    assert_eq!(unsafe { has(trailing, b"10.1.2.3") }, MATCH);
    unsafe { ip_matcher_free(trailing) };
}

#[test]
fn lookup_reports_no_match_separately_from_boundary_errors() {
    assert_eq!(
        unsafe { ip_matcher_has(ptr::null(), b"127.0.0.1".as_ptr(), 9) },
        ERROR
    );

    let handle = unsafe { ip_matcher_create(ptr::null(), 0) };
    assert!(!handle.is_null());
    assert_eq!(unsafe { ip_matcher_has(handle, ptr::null(), 0) }, NO_MATCH);
    assert_eq!(unsafe { ip_matcher_has(handle, ptr::null(), 1) }, ERROR);
    assert_eq!(unsafe { has(handle, &[0xc3, 0x28]) }, ERROR);
    assert_eq!(unsafe { has(handle, b"not-an-address") }, NO_MATCH);

    let oversized = vec![b'0'; 129];
    assert_eq!(unsafe { has(handle, &oversized) }, ERROR);
    unsafe { ip_matcher_free(handle) };
}
