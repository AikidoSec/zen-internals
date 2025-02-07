use crate::js_injection::detect_js_injection::detect_js_injection_str;
use crate::sql_injection::detect_sql_injection::detect_sql_injection_str;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::panic;
use std::str;

#[no_mangle]
pub extern "C" fn detect_sql_injection(
    query: *const c_char,
    userinput: *const c_char,
    dialect: c_int,
) -> c_int {
    // Returns an integer value, representing a boolean (1 = true, 0 = false, 2 = error)
    return panic::catch_unwind(|| {
        // Check if the pointers are null
        if query.is_null() || userinput.is_null() {
            return 2;
        }

        let query_bytes = unsafe { CStr::from_ptr(query).to_bytes() };
        let query_str = match str::from_utf8(query_bytes) {
            Ok(s) => s,
            Err(_) => return 2, // Return error code if invalid UTF-8
        };

        let userinput_bytes = unsafe { CStr::from_ptr(userinput).to_bytes() };
        let userinput_str = match str::from_utf8(userinput_bytes) {
            Ok(s) => s,
            Err(_) => return 2, // Return error code if invalid UTF-8
        };

        if detect_sql_injection_str(query_str, userinput_str, dialect) {
            return 1;
        }

        return 0;
    })
    .unwrap_or(2);
}

#[no_mangle]
pub extern "C" fn detect_js_injection(
    code: *const c_char,
    userinput: *const c_char,
    sourcetype: c_int,
) -> c_int {
    // Returns an integer value, representing a boolean (1 = true, 0 = false, 2 = error)
    return panic::catch_unwind(|| {
        // Check if the pointers are null
        if code.is_null() || userinput.is_null() {
            return 2;
        }

        let code_bytes = unsafe { CStr::from_ptr(code).to_bytes() };
        let code_str = match str::from_utf8(code_bytes) {
            Ok(s) => s,
            Err(_) => return 2, // Return error code if invalid UTF-8
        };

        let userinput_bytes = unsafe { CStr::from_ptr(userinput).to_bytes() };
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
