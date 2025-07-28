use crate::js_injection::detect_js_injection::detect_js_injection_str;
use crate::sql_injection::detect_sql_injection::{detect_sql_injection_str, DetectionReason};
use std::os::raw::c_int;
use std::panic;
use std::str;

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
