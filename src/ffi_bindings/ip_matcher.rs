use crate::ip_matcher::IpMatcher;
use std::os::raw::c_int;
use std::panic;
use std::ptr;
use std::str;

const MAX_NETWORKS: usize = 1_000_000;
const MAX_INPUT_BYTES: usize = 64 * 1024 * 1024;
const MAX_LOOKUP_BYTES: usize = 128;
const NO_MATCH: c_int = 0;
const MATCH: c_int = 1;
const ERROR: c_int = 2;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct IpMatcherByteSlice {
    pub ptr: *const u8,
    pub len: usize,
}

pub struct IpMatcherHandle {
    matcher: IpMatcher,
}

/// Creates an immutable matcher. Invalid network strings are ignored.
///
/// Returns null for invalid FFI input, exceeded limits, or a caught panic.
///
/// # Safety
///
/// For `network_count` in `1..=1_000_000`, `networks` must reference that many aligned,
/// initialized descriptors. Each nonempty descriptor must reference `len` contiguous,
/// initialized bytes. All referenced memory must remain valid and unchanged for this call.
/// Free a non-null result exactly once with `ip_matcher_free`.
#[no_mangle]
pub unsafe extern "C" fn ip_matcher_create(
    networks: *const IpMatcherByteSlice,
    network_count: usize,
) -> *mut IpMatcherHandle {
    panic::catch_unwind(|| unsafe {
        create_matcher(networks, network_count)
            .map(|matcher| Box::into_raw(Box::new(IpMatcherHandle { matcher })))
    })
    .ok()
    .and_then(Result::ok)
    .unwrap_or(ptr::null_mut())
}

unsafe fn create_matcher(
    networks: *const IpMatcherByteSlice,
    network_count: usize,
) -> Result<IpMatcher, ()> {
    if network_count > MAX_NETWORKS || (network_count > 0 && networks.is_null()) {
        return Err(());
    }

    let descriptors = if network_count == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(networks, network_count) }
    };

    let mut total_input_bytes = 0_usize;
    for descriptor in descriptors {
        if descriptor.len > 0 && descriptor.ptr.is_null() {
            return Err(());
        }
        total_input_bytes = total_input_bytes.checked_add(descriptor.len).ok_or(())?;
        if total_input_bytes > MAX_INPUT_BYTES {
            return Err(());
        }
    }

    let mut network_strings = Vec::with_capacity(network_count.min(1024));
    for descriptor in descriptors {
        let bytes = if descriptor.len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(descriptor.ptr, descriptor.len) }
        };
        network_strings.push(str::from_utf8(bytes).map_err(|_| ())?);
    }

    Ok(IpMatcher::new(network_strings))
}

/// Returns the number of bytes allocated by a matcher, or zero for an invalid handle or panic.
///
/// # Safety
///
/// `handle` must be null or a live pointer returned by `ip_matcher_create`.
#[no_mangle]
pub unsafe extern "C" fn ip_matcher_memory_size(handle: *const IpMatcherHandle) -> usize {
    panic::catch_unwind(|| {
        if handle.is_null() {
            0
        } else {
            unsafe { &*handle }.matcher.memory_size()
        }
    })
    .unwrap_or(0)
}

/// Returns `1` for a match, `0` for no match, and `2` for invalid FFI input or a caught panic.
///
/// # Safety
///
/// `handle` must remain live for this call. Concurrent lookups are allowed, but freeing the handle
/// concurrently is not. For `network_len` in `1..=128`, `network` must reference that many
/// contiguous, initialized bytes that remain valid and unchanged for this call.
#[no_mangle]
pub unsafe extern "C" fn ip_matcher_has(
    handle: *const IpMatcherHandle,
    network: *const u8,
    network_len: usize,
) -> c_int {
    panic::catch_unwind(|| {
        if handle.is_null()
            || network_len > MAX_LOOKUP_BYTES
            || (network_len > 0 && network.is_null())
        {
            return ERROR;
        }

        let bytes = if network_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(network, network_len) }
        };
        let Ok(network) = str::from_utf8(bytes) else {
            return ERROR;
        };
        let matcher = unsafe { &*handle };
        if matcher.matcher.has(network) {
            MATCH
        } else {
            NO_MATCH
        }
    })
    .unwrap_or(ERROR)
}

/// Releases an opaque IP matcher handle. Passing null has no effect.
///
/// # Safety
///
/// `handle` must be null or a pointer returned by `ip_matcher_create` that has not been freed.
/// No lookup may use the handle during or after this call.
#[no_mangle]
pub unsafe extern "C" fn ip_matcher_free(handle: *mut IpMatcherHandle) {
    if handle.is_null() {
        return;
    }

    let _ = panic::catch_unwind(|| unsafe {
        drop(Box::from_raw(handle));
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::NonNull;

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
        assert!(unsafe { ip_matcher_create(ptr::null(), MAX_NETWORKS + 1) }.is_null());

        let null_buffer = IpMatcherByteSlice {
            ptr: ptr::null(),
            len: 1,
        };
        assert!(unsafe { ip_matcher_create(&null_buffer, 1) }.is_null());

        let invalid_utf8 = descriptor(&[0xc3, 0x28]);
        assert!(unsafe { ip_matcher_create(&invalid_utf8, 1) }.is_null());

        let oversized = IpMatcherByteSlice {
            ptr: NonNull::<u8>::dangling().as_ptr(),
            len: MAX_INPUT_BYTES + 1,
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

        let oversized = vec![b'0'; MAX_LOOKUP_BYTES + 1];
        assert_eq!(unsafe { has(handle, &oversized) }, ERROR);
        unsafe { ip_matcher_free(handle) };
    }
}
