use crate::route_builder::build_route_from_url::build_route_from_url_str;
use crate::shell_injection::detect_shell_injection::detect_shell_injection_stringified;
use crate::sql_injection::detect_sql_injection::detect_sql_injection_str;
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn wasm_build_route_from_url(url: &str) -> String {
    build_route_from_url_str(url).unwrap_or("".to_string())
}

#[wasm_bindgen]
pub fn wasm_detect_shell_injection(command: &str, userinput: &str) -> bool {
    detect_shell_injection_stringified(command, userinput)
}

#[wasm_bindgen]
pub fn wasm_detect_sql_injection(query: &str, userinput: &str, dialect: i32) -> bool {
    detect_sql_injection_str(query, userinput, dialect)
}
