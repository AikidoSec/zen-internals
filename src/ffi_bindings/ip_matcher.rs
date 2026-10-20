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

pub struct IpMatcherHandle {
    matcher: IpMatcher,
}

/// Creates an immutable matcher from a UTF-8 string of newline-separated networks. Each network
/// is an IPv4 or IPv6 address with an optional `/prefix` length. Invalid networks are rejected.
/// An empty string creates an empty matcher.
///
/// Valid networks are never rejected, even if another network already covers them.
///
/// Returns null for invalid FFI input, exceeded limits, or a caught panic.
///
/// # Safety
///
/// For `networks_len` greater than zero, `networks` must point to `networks_len` initialized
/// bytes that remain valid and unchanged for this call. Free a non-null result exactly once
/// with `ip_matcher_free`.
#[no_mangle]
pub unsafe extern "C" fn ip_matcher_create(
    networks: *const u8,
    networks_len: usize,
) -> *mut IpMatcherHandle {
    panic::catch_unwind(|| unsafe {
        create_matcher(networks, networks_len)
            .map(|matcher| Box::into_raw(Box::new(IpMatcherHandle { matcher })))
    })
    .ok()
    .and_then(Result::ok)
    .unwrap_or(ptr::null_mut())
}

unsafe fn create_matcher(networks: *const u8, networks_len: usize) -> Result<IpMatcher, ()> {
    if networks_len > MAX_INPUT_BYTES || (networks_len > 0 && networks.is_null()) {
        return Err(());
    }

    let bytes = if networks_len == 0 {
        &[]
    } else {
        unsafe { std::slice::from_raw_parts(networks, networks_len) }
    };

    let networks = str::from_utf8(bytes).map_err(|_| ())?;

    if networks.is_empty() {
        return Ok(IpMatcher::new([] as [&str; 0]));
    }

    let separators = bytes.iter().filter(|&&byte| byte == b'\n').count();
    if separators >= MAX_NETWORKS {
        return Err(());
    }

    Ok(IpMatcher::new(networks.split('\n')))
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

/// Returns how many of the networks passed to `ip_matcher_create` were rejected, or zero for
/// an invalid handle or panic.
///
/// # Safety
///
/// `handle` must be null or a live pointer returned by `ip_matcher_create`.
#[no_mangle]
pub unsafe extern "C" fn ip_matcher_rejected_count(handle: *const IpMatcherHandle) -> usize {
    panic::catch_unwind(|| {
        if handle.is_null() {
            0
        } else {
            unsafe { &*handle }.matcher.rejected_count()
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
