use crate::route_builder::build_route_from_url::build_route_from_url_str;
use crate::shell_injection::detect_shell_injection::detect_shell_injection_stringified;
use std::ffi::{CStr, CString};
use std::os::raw::{c_char, c_int};
use std::str;

#[no_mangle]
pub extern "C" fn build_route_from_url(url: *const c_char) -> *mut c_char {
    // Check if the pointers are null
    if url.is_null() {
        eprintln!("Received null pointer for URL.");
        return CString::new("").expect("").into_raw();
    }
    let url_bytes = unsafe { CStr::from_ptr(url).to_bytes() };
    let url_str = str::from_utf8(url_bytes).unwrap();

    let route = build_route_from_url_str(url_str).unwrap_or("".to_string());
    let c_string = CString::new(route).expect("CString::new failed");
    c_string.into_raw()
}

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
