use crate::route_builder::build_route_from_url::build_route_from_url_str;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
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
