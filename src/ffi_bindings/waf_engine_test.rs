use super::free_string;
use super::waf_engine::{
    waf_engine_create, waf_engine_free, waf_engine_match, waf_engine_memory_size, WafEngineHandle,
};
use serde_json::Value;
use std::ffi::CStr;
use std::ptr;

unsafe fn create(rules: &str) -> *mut WafEngineHandle {
    unsafe { waf_engine_create(rules.as_ptr(), rules.len()) }
}

unsafe fn match_request(handle: *const WafEngineHandle, request: &str) -> Value {
    let result_pointer = unsafe { waf_engine_match(handle, request.as_ptr(), request.len()) };
    let result = unsafe { CStr::from_ptr(result_pointer) }
        .to_str()
        .unwrap()
        .to_owned();
    unsafe { free_string(result_pointer) };
    serde_json::from_str(&result).unwrap()
}

#[test]
fn waf_engine_handle_lifecycle_preserves_matching_behavior() {
    let rules = r#"[{"id":"admin","expression":"http.request.uri.path contains \"/admin\"","action":"block"}]"#;
    let empty_handle = unsafe { create("[]") };
    let handle = unsafe { create(rules) };

    assert!(!empty_handle.is_null());
    assert!(!handle.is_null());
    assert!(
        unsafe { waf_engine_memory_size(handle) } > unsafe { waf_engine_memory_size(empty_handle) }
    );
    assert_eq!(
        unsafe { match_request(handle, r#"{"path":"/admin/users","ip_src":"127.0.0.1"}"#,) }
            ["rule_id"],
        "admin"
    );
    assert_eq!(
        unsafe { match_request(handle, r#"{"path":"/products","ip_src":"127.0.0.1"}"#,) }
            ["matched"],
        false
    );

    unsafe { waf_engine_free(handle) };
    unsafe { waf_engine_free(empty_handle) };
    unsafe { waf_engine_free(ptr::null_mut()) };
}

#[test]
fn waf_engine_creation_rejects_invalid_input() {
    assert_eq!(unsafe { waf_engine_memory_size(ptr::null()) }, 0);
    assert!(unsafe { waf_engine_create(ptr::null(), 0) }.is_null());
    assert!(unsafe { create("not json") }.is_null());
    assert!(
        unsafe { create(r#"[{"id":"bad","expression":"not valid !!!","action":"block"}]"#) }
            .is_null()
    );
}

#[test]
fn waf_engine_handle_supports_matching_from_another_thread() {
    let rules = r#"[{"id":"shared","expression":"http.request.uri.path contains \"/admin\"","action":"block"}]"#;
    let handle = unsafe { create(rules) };
    assert!(!handle.is_null());

    let handle_address = handle as usize;
    let result = std::thread::spawn(move || {
        let handle = handle_address as *const WafEngineHandle;
        unsafe { match_request(handle, r#"{"path":"/admin","ip_src":"127.0.0.1"}"#) }
    })
    .join()
    .unwrap();

    assert_eq!(result["matched"], true);
    unsafe { waf_engine_free(handle) };
}
