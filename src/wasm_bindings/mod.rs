use crate::idor::idor_analyze_sql::idor_analyze_sql;
use crate::js_injection::detect_js_injection::detect_js_injection_str;
use crate::sql_injection::detect_sql_injection::{detect_sql_injection_str, DetectionReason};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn wasm_detect_sql_injection(query: &str, userinput: &str, dialect: i32) -> i32 {
    let detection_results = detect_sql_injection_str(query, userinput, dialect);

    if let DetectionReason::FailedToTokenizeQuery = detection_results.reason {
        // make a special exception for failing to tokenize query (report code 3)
        return 3;
    }

    if detection_results.detected {
        1
    } else {
        0
    }
}

#[wasm_bindgen]
pub fn wasm_detect_js_injection(code: &str, userinput: &str, sourcetype: i32) -> bool {
    detect_js_injection_str(code, userinput, sourcetype)
}

#[wasm_bindgen]
pub fn wasm_idor_analyze_sql(query: &str, dialect: i32) -> JsValue {
    match idor_analyze_sql(query, dialect) {
        Ok(selects) => serde_wasm_bindgen::to_value(&selects).unwrap_or(JsValue::NULL),
        Err(e) => {
            let obj = js_sys::Object::new();
            let _ = js_sys::Reflect::set(&obj, &"error".into(), &e.into());
            obj.into()
        }
    }
}
