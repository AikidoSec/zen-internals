use crate::js_injection::detect_js_injection::detect_js_injection_str;
use crate::sql_injection::detect_sql_injection::detect_sql_injection_str;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn wasm_detect_sql_injection(query: &str, userinput: &str, dialect: i32) -> bool {
    detect_sql_injection_str(query, userinput, dialect)
}

#[wasm_bindgen]
pub fn wasm_detect_js_injection(code: &str, userinput: &str, sourcetype: i32) -> bool {
    detect_js_injection_str(code, userinput, sourcetype)
}
