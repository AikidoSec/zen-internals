use super::ip_matcher::{
    ip_matcher_create, ip_matcher_free, ip_matcher_has, ip_matcher_memory_size, IpMatcherByteSlice,
    IpMatcherHandle,
};
use std::os::raw::c_int;
use std::ptr;
use std::ptr::NonNull;

const NO_MATCH: c_int = 0;
const MATCH: c_int = 1;
const ERROR: c_int = 2;

fn descriptor(value: &[u8]) -> IpMatcherByteSlice {
    IpMatcherByteSlice {
        ptr: value.as_ptr(),
        len: value.len(),
    }
}

unsafe fn has(handle: *const IpMatcherHandle, value: &[u8]) -> c_int {
    unsafe { ip_matcher_has(handle, value.as_ptr(), value.len()) }
}

#[test]
fn matcher_handle_lifecycle_preserves_matcher_behavior() {
    let values: &[&[u8]] = &[b"10.0.0.42/8", b"2001:db8::/32", b"invalid network"];
    let descriptors: Vec<_> = values.iter().map(|value| descriptor(value)).collect();

    let handle = unsafe { ip_matcher_create(descriptors.as_ptr(), descriptors.len()) };
    assert!(!handle.is_null());
    assert!(unsafe { ip_matcher_memory_size(handle) } > 0);
    assert_eq!(unsafe { has(handle, b"10.255.255.255") }, MATCH);
    assert_eq!(unsafe { has(handle, b"[2001:db8::1]") }, MATCH);
    assert_eq!(unsafe { has(handle, b"192.0.2.1") }, NO_MATCH);
    unsafe { ip_matcher_free(handle) };
    unsafe { ip_matcher_free(ptr::null_mut()) };
}

#[test]
fn creation_rejects_structural_errors_and_limits() {
    assert_eq!(unsafe { ip_matcher_memory_size(ptr::null()) }, 0);
    assert!(unsafe { ip_matcher_create(ptr::null(), 1) }.is_null());
    assert!(unsafe { ip_matcher_create(ptr::null(), 1_000_001) }.is_null());

    let null_buffer = IpMatcherByteSlice {
        ptr: ptr::null(),
        len: 1,
    };
    assert!(unsafe { ip_matcher_create(&null_buffer, 1) }.is_null());

    let invalid_utf8 = descriptor(&[0xc3, 0x28]);
    assert!(unsafe { ip_matcher_create(&invalid_utf8, 1) }.is_null());

    let oversized = IpMatcherByteSlice {
        ptr: NonNull::<u8>::dangling().as_ptr(),
        len: 64 * 1024 * 1024 + 1,
    };
    assert!(unsafe { ip_matcher_create(&oversized, 1) }.is_null());
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
