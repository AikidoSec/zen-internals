use crate::idor::idor_analyze_sql::idor_analyze_sql;
use crate::js_injection::detect_js_injection::detect_js_injection_str;
use crate::sql_injection::detect_sql_injection::{detect_sql_injection_str, DetectionReason};
use crate::waf::waf_evaluate::WafEngine;
use crate::waf::waf_result::RuleInput;
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

#[wasm_bindgen]
pub struct WasmWafEngine {
    engine: WafEngine,
}

#[wasm_bindgen]
pub fn create_waf_engine(rules_json: &str) -> Result<WasmWafEngine, JsValue> {
    let rules: Vec<RuleInput> =
        serde_json::from_str(rules_json).map_err(|error| JsValue::from_str(&error.to_string()))?;
    let engine = WafEngine::from_rules(&rules).map_err(|result| {
        JsValue::from_str(result.error.as_deref().unwrap_or("Invalid WAF rules"))
    })?;
    Ok(WasmWafEngine { engine })
}

#[wasm_bindgen]
impl WasmWafEngine {
    pub fn get_size(&self) -> usize {
        self.engine.memory_size()
    }

    pub fn match_rules(&self, request_json: &str) -> JsValue {
        let request = match serde_json::from_str(request_json) {
            Ok(request) => request,
            Err(_) => return no_waf_match(),
        };

        match self.engine.evaluate(&request) {
            Ok(result) => serde_wasm_bindgen::to_value(&result).unwrap_or_else(|_| no_waf_match()),
            Err(_) => no_waf_match(),
        }
    }
}

fn no_waf_match() -> JsValue {
    let result = js_sys::Object::new();
    let _ = js_sys::Reflect::set(&result, &"matched".into(), &false.into());
    result.into()
}
