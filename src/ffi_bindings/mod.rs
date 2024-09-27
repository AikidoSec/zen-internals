use crate::shell_injection::detect_shell_injection::detect_shell_injection_stringified;
use crate::sql_injection::detect_sql_injection::detect_sql_injection_str;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::str;

#[no_mangle]
pub extern "C" fn detect_shell_injection(
    command: *const c_char,
    userinput: *const c_char,
) -> c_int {
    // Check if the pointers are null
    if command.is_null() || userinput.is_null() {
        eprintln!("Received null pointer for command or userinput.");
        return 0; // Handle the error as needed
    }
    let command_bytes = unsafe { CStr::from_ptr(command).to_bytes() };
    let userinput_bytes = unsafe { CStr::from_ptr(userinput).to_bytes() };

    let command_str = str::from_utf8(command_bytes).unwrap();
    let userinput_str = str::from_utf8(userinput_bytes).unwrap();

    // Returns an integer value, representing a boolean (1 = true, 0 = false).
    if detect_shell_injection_stringified(command_str, userinput_str) {
        1
    } else {
        0
    }
}

#[no_mangle]
pub extern "C" fn detect_sql_injection(
    query: *const c_char,
    userinput: *const c_char,
    dialect: c_int,
) -> c_int {
    // Check if the pointers are null
    if query.is_null() || userinput.is_null() {
        eprintln!("Received null pointer for command or userinput.");
        return 0; // Handle the error as needed
    }
    let query_bytes = unsafe { CStr::from_ptr(query).to_bytes() };
    let userinput_bytes = unsafe { CStr::from_ptr(userinput).to_bytes() };

    let query_str = str::from_utf8(query_bytes).unwrap();
    let userinput_str = str::from_utf8(userinput_bytes).unwrap();

    // Returns an integer value, representing a boolean (1 = true, 0 = false).
    if detect_sql_injection_str(query_str, userinput_str, dialect) {
        1
    } else {
        0
    }
}
