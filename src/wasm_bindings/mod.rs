use crate::idor::idor_analyze_sql::idor_analyze_sql;
use crate::js_injection::detect_js_injection::detect_js_injection_str;
use crate::sql_injection::detect_sql_injection::{detect_sql_injection_str, DetectionReason};
use crate::waf::waf_evaluate::WafEngine;
use crate::waf::waf_result::RuleInput;
use std::cell::RefCell;
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

// WAF engine singleton - WASM is single-threaded so RefCell is safe
thread_local! {
    static WAF_ENGINE: RefCell<WafEngine> = RefCell::new(WafEngine::new());
}

#[wasm_bindgen]
pub fn wasm_waf_set_rules(rules_json: &str) -> JsValue {
    let rule_inputs: Vec<RuleInput> = match serde_json::from_str(rules_json) {
        Ok(rules) => rules,
        Err(e) => {
            let obj = js_sys::Object::new();
            let _ = js_sys::Reflect::set(&obj, &"success".into(), &false.into());
            let _ = js_sys::Reflect::set(&obj, &"error".into(), &e.to_string().into());
            return obj.into();
        }
    };

    WAF_ENGINE.with(|engine| {
        let result = engine.borrow_mut().set_rules(&rule_inputs);
        serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL)
    })
}

#[wasm_bindgen]
pub fn wasm_waf_evaluate(request_json: &str) -> JsValue {
    let request = match serde_json::from_str(request_json) {
        Ok(req) => req,
        Err(_) => {
            let obj = js_sys::Object::new();
            let _ = js_sys::Reflect::set(&obj, &"matched".into(), &false.into());
            return obj.into();
        }
    };

    WAF_ENGINE.with(|engine| match engine.borrow().evaluate(&request) {
        Ok(result) => serde_wasm_bindgen::to_value(&result).unwrap_or(JsValue::NULL),
        Err(e) => {
            let obj = js_sys::Object::new();
            let _ = js_sys::Reflect::set(&obj, &"matched".into(), &false.into());
            let _ = js_sys::Reflect::set(&obj, &"error".into(), &e.into());
            obj.into()
        }
    })
}
