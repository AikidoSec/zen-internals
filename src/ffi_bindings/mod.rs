use crate::shell_injection::detect_shell_injection::detect_shell_injection_stringified;
use crate::sql_injection::detect_sql_injection::detect_sql_injection_str;
use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::panic;
use std::str;

#[no_mangle]
pub extern "C" fn detect_shell_injection(
    command: *const c_char,
    userinput: *const c_char,
) -> c_int {
    // Returns an integer value, representing a boolean (1 = true, 0 = false, 2 = error)
    return panic::catch_unwind(|| {
        // Check if the pointers are null
        if command.is_null() || userinput.is_null() {
            return 2;
        }

        let command_bytes = unsafe { CStr::from_ptr(command).to_bytes() };
        let userinput_bytes = unsafe { CStr::from_ptr(userinput).to_bytes() };

        let command_str = str::from_utf8(command_bytes).unwrap();
        let userinput_str = str::from_utf8(userinput_bytes).unwrap();

        if detect_shell_injection_stringified(command_str, userinput_str) {
            return 1;
        }

        return 0;
    })
    .unwrap_or(2);
}

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
        let userinput_bytes = unsafe { CStr::from_ptr(userinput).to_bytes() };

        let query_str = str::from_utf8(query_bytes).unwrap();
        let userinput_str = str::from_utf8(userinput_bytes).unwrap();

        if detect_sql_injection_str(query_str, userinput_str, dialect) {
            return 1;
        }

        return 0;
    })
    .unwrap_or(2);
}
