use crate::idor::idor_analyze_sql::idor_analyze_sql;
use crate::js_injection::detect_js_injection::detect_js_injection_str;
use crate::sql_injection::detect_sql_injection::{detect_sql_injection_str, DetectionReason};
use crate::waf::waf_evaluate::WafEngine;
use crate::waf::waf_result::RuleInput;
use std::cell::RefCell;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::panic;
use std::str;

#[cfg(target_arch = "wasm32")]
use std::alloc::{alloc, dealloc, Layout};

#[no_mangle]
pub extern "C" fn detect_sql_injection(
    query: *const u8,
    query_len: usize,
    userinput: *const u8,
    userinput_len: usize,
    dialect: c_int,
) -> c_int {
    // Returns an integer value, representing a boolean (1 = true, 0 = false, 2 = error)
    return panic::catch_unwind(|| {
        // Check if the pointers are null
        if query.is_null() || userinput.is_null() {
            return 2;
        }

        if query_len == 0 || userinput_len == 0 {
            return 2;
        }

        let query_bytes = unsafe { std::slice::from_raw_parts(query, query_len) };
        let query_str = match str::from_utf8(query_bytes) {
            Ok(s) => s,
            Err(_) => return 2, // Return error code if invalid UTF-8
        };

        let userinput_bytes = unsafe { std::slice::from_raw_parts(userinput, userinput_len) };
        let userinput_str = match str::from_utf8(userinput_bytes) {
            Ok(s) => s,
            Err(_) => return 2, // Return error code if invalid UTF-8
        };

        let detection_results = detect_sql_injection_str(query_str, userinput_str, dialect);
        if let DetectionReason::FailedToTokenizeQuery = detection_results.reason {
            // make a special exception for failing to tokenize query (report code 3)
            return 3;
        }
        if detection_results.detected {
            return 1;
        }
        return 0;
    })
    .unwrap_or(2);
}

#[no_mangle]
pub extern "C" fn detect_js_injection(
    code: *const u8,
    code_len: usize,
    userinput: *const u8,
    userinput_len: usize,
    sourcetype: c_int,
) -> c_int {
    // Returns an integer value, representing a boolean (1 = true, 0 = false, 2 = error)
    return panic::catch_unwind(|| {
        // Check if the pointers are null
        if code.is_null() || userinput.is_null() {
            return 2;
        }

        if code_len == 0 || userinput_len == 0 {
            return 2;
        }

        let code_bytes = unsafe { std::slice::from_raw_parts(code, code_len) };
        let code_str = match str::from_utf8(code_bytes) {
            Ok(s) => s,
            Err(_) => return 2, // Return error code if invalid UTF-8
        };

        let userinput_bytes = unsafe { std::slice::from_raw_parts(userinput, userinput_len) };
        let userinput_str = match str::from_utf8(userinput_bytes) {
            Ok(s) => s,
            Err(_) => return 2, // Return error code if invalid UTF-8
        };

        if detect_js_injection_str(code_str, userinput_str, sourcetype) {
            return 1;
        }

        return 0;
    })
    .unwrap_or(2);
}

/// Allocates memory in WASM linear memory
///
/// # Satefy
///
/// The returned pointer must be deallocated using `wasm_free` with the exact same size.
/// The allocated memory is uninitialized.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn wasm_alloc(size: usize) -> *mut u8 {
    let layout = Layout::from_size_align(size, 1).unwrap();
    unsafe { alloc(layout) }
}

/// Deallocates memory previously allocated by `wasm_alloc`
///
/// # Satefy
///
/// - `ptr` must have been allocated by `wasm_alloc`
/// - `size` must be the exact size passed to `wasm_alloc`
/// - `ptr` must not have been previously freed
/// - After calling this function, `ptr` must not be used
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn wasm_free(ptr: *mut u8, size: usize) {
    let layout = Layout::from_size_align(size, 1).unwrap();
    dealloc(ptr, layout)
}

#[no_mangle]
pub extern "C" fn idor_analyze_sql_ffi(
    query: *const u8,
    query_len: usize,
    dialect: c_int,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        if query.is_null() || query_len == 0 {
            return CString::new(r#"{"error":"Invalid query pointer or length"}"#)
                .unwrap()
                .into_raw();
        }

        let query_bytes = unsafe { std::slice::from_raw_parts(query, query_len) };
        let query_str = match str::from_utf8(query_bytes) {
            Ok(s) => s,
            Err(_) => {
                return CString::new(r#"{"error":"Invalid UTF-8 in query"}"#)
                    .unwrap()
                    .into_raw();
            }
        };

        let json = match idor_analyze_sql(query_str, dialect) {
            Ok(results) => serde_json::to_string(&results)
                .unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e)),
            Err(e) => format!(r#"{{"error":"{}"}}"#, e),
        };

        CString::new(json)
            .unwrap_or_else(|_| CString::new(r#"{"error":"Failed to create C string"}"#).unwrap())
            .into_raw()
    });

    result.unwrap_or_else(|_| {
        CString::new(r#"{"error":"Internal error"}"#)
            .unwrap()
            .into_raw()
    })
}

#[no_mangle]
pub unsafe extern "C" fn free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

// WAF engine singleton
thread_local! {
    static WAF_ENGINE: RefCell<WafEngine> = RefCell::new(WafEngine::new());
}

#[no_mangle]
pub extern "C" fn waf_set_rules(
    rules_json: *const u8,
    rules_json_len: usize,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        if rules_json.is_null() || rules_json_len == 0 {
            return CString::new(r#"{"success":false,"error":"Invalid input"}"#)
                .unwrap()
                .into_raw();
        }

        let json_bytes = unsafe { std::slice::from_raw_parts(rules_json, rules_json_len) };
        let json_str = match str::from_utf8(json_bytes) {
            Ok(s) => s,
            Err(_) => {
                return CString::new(r#"{"success":false,"error":"Invalid UTF-8"}"#)
                    .unwrap()
                    .into_raw();
            }
        };

        let rule_inputs: Vec<RuleInput> = match serde_json::from_str(json_str) {
            Ok(rules) => rules,
            Err(e) => {
                let json = format!(r#"{{"success":false,"error":"{}"}}"#, e);
                return CString::new(json).unwrap().into_raw();
            }
        };

        WAF_ENGINE.with(|engine| {
            let result = engine.borrow_mut().set_rules(&rule_inputs);
            let json = serde_json::to_string(&result)
                .unwrap_or_else(|e| format!(r#"{{"success":false,"error":"{}"}}"#, e));
            CString::new(json).unwrap().into_raw()
        })
    });

    result.unwrap_or_else(|_| {
        CString::new(r#"{"success":false,"error":"Internal error"}"#)
            .unwrap()
            .into_raw()
    })
}

#[no_mangle]
pub extern "C" fn waf_evaluate(
    request_json: *const u8,
    request_json_len: usize,
) -> *mut c_char {
    let result = panic::catch_unwind(|| {
        if request_json.is_null() || request_json_len == 0 {
            return CString::new(r#"{"matched":false}"#).unwrap().into_raw();
        }

        let json_bytes =
            unsafe { std::slice::from_raw_parts(request_json, request_json_len) };
        let json_str = match str::from_utf8(json_bytes) {
            Ok(s) => s,
            Err(_) => return CString::new(r#"{"matched":false}"#).unwrap().into_raw(),
        };

        let request = match serde_json::from_str(json_str) {
            Ok(req) => req,
            Err(_) => return CString::new(r#"{"matched":false}"#).unwrap().into_raw(),
        };

        WAF_ENGINE.with(|engine| {
            let json = match engine.borrow().evaluate(&request) {
                Ok(result) => serde_json::to_string(&result)
                    .unwrap_or_else(|_| r#"{"matched":false}"#.to_string()),
                Err(e) => format!(r#"{{"matched":false,"error":"{}"}}"#, e),
            };
            CString::new(json).unwrap().into_raw()
        })
    });

    result.unwrap_or_else(|_| {
        CString::new(r#"{"matched":false}"#).unwrap().into_raw()
    })
}
