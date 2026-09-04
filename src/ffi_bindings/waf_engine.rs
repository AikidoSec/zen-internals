use crate::waf::waf_evaluate::WafEngine;
use crate::waf::waf_result::{RequestData, RuleInput};
use std::ffi::CString;
use std::os::raw::c_char;
use std::panic::{self, AssertUnwindSafe};
use std::ptr;
use std::str;

pub struct WafEngineHandle {
    engine: WafEngine,
}

/// Creates an immutable WAF engine from JSON rules.
///
/// Returns null for invalid FFI input, invalid JSON, invalid rules, or a caught panic.
///
/// # Safety
///
/// `rules_json` must reference `rules_json_len` contiguous, initialized bytes that remain valid
/// and unchanged for this call. Free a non-null result exactly once with `waf_engine_free`.
#[no_mangle]
pub unsafe extern "C" fn waf_engine_create(
    rules_json: *const u8,
    rules_json_len: usize,
) -> *mut WafEngineHandle {
    panic::catch_unwind(AssertUnwindSafe(|| unsafe {
        create_engine(rules_json, rules_json_len)
    }))
    .ok()
    .and_then(Result::ok)
    .map(|engine| Box::into_raw(Box::new(WafEngineHandle { engine })))
    .unwrap_or(ptr::null_mut())
}

unsafe fn create_engine(rules_json: *const u8, rules_json_len: usize) -> Result<WafEngine, ()> {
    if rules_json_len == 0 || rules_json.is_null() {
        return Err(());
    }

    let bytes = unsafe { std::slice::from_raw_parts(rules_json, rules_json_len) };
    let rules: Vec<RuleInput> =
        serde_json::from_str(str::from_utf8(bytes).map_err(|_| ())?).map_err(|_| ())?;
    WafEngine::from_rules(&rules).map_err(|_| ())
}

/// Returns an estimate of native memory used by an engine, or zero for a null handle or panic.
///
/// # Safety
///
/// `handle` must be null or a live pointer returned by `waf_engine_create`.
#[no_mangle]
pub unsafe extern "C" fn waf_engine_memory_size(handle: *const WafEngineHandle) -> usize {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() {
            0
        } else {
            unsafe { &*handle }.engine.memory_size()
        }
    }))
    .unwrap_or(0)
}

/// Matches a request against an immutable WAF engine.
///
/// Returns an allocated JSON string. Release it with `free_string`.
///
/// # Safety
///
/// `handle` must remain live for this call. Concurrent matches are allowed, but freeing the handle
/// concurrently is not. `request_json` must reference `request_json_len` contiguous, initialized
/// bytes that remain valid and unchanged for this call.
#[no_mangle]
pub unsafe extern "C" fn waf_engine_match(
    handle: *const WafEngineHandle,
    request_json: *const u8,
    request_json_len: usize,
) -> *mut c_char {
    panic::catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || request_json_len == 0 || request_json.is_null() {
            return no_match();
        }

        let bytes = unsafe { std::slice::from_raw_parts(request_json, request_json_len) };
        let request: RequestData = match str::from_utf8(bytes)
            .ok()
            .and_then(|json| serde_json::from_str(json).ok())
        {
            Some(request) => request,
            None => return no_match(),
        };

        let result = unsafe { &*handle }.engine.evaluate(&request);
        let json = match result {
            Ok(result) => serde_json::to_string(&result)
                .unwrap_or_else(|_| r#"{"matched":false}"#.to_string()),
            Err(_) => r#"{"matched":false}"#.to_string(),
        };
        CString::new(json)
            .unwrap_or_else(|_| CString::new(r#"{"matched":false}"#).unwrap())
            .into_raw()
    }))
    .unwrap_or_else(|_| no_match())
}

fn no_match() -> *mut c_char {
    CString::new(r#"{"matched":false}"#).unwrap().into_raw()
}

/// Releases an opaque WAF engine handle. Passing null has no effect.
///
/// # Safety
///
/// `handle` must be null or a pointer returned by `waf_engine_create` that has not been freed.
/// No match may use the handle during or after this call.
#[no_mangle]
pub unsafe extern "C" fn waf_engine_free(handle: *mut WafEngineHandle) {
    if handle.is_null() {
        return;
    }

    let _ = panic::catch_unwind(AssertUnwindSafe(|| unsafe {
        drop(Box::from_raw(handle));
    }));
}
