use crate::idor::idor_analyze_sql::idor_analyze_sql as idor_analyze_sql_core;
use crate::sql_injection::detect_sql_injection::{detect_sql_injection_str, DetectionReason};
use pyo3::prelude::*;
use std::panic;

#[pyfunction]
fn detect_sql_injection(query: &str, user_input: &str, dialect: i32) -> i32 {
    panic::catch_unwind(|| {
        let result = detect_sql_injection_str(query, user_input, dialect);
        if let DetectionReason::FailedToTokenizeQuery = result.reason {
            return 3;
        }
        if result.detected {
            1
        } else {
            0
        }
    })
    .unwrap_or(2)
}

#[pyfunction]
fn idor_analyze_sql(query: &str, dialect: i32) -> String {
    panic::catch_unwind(|| match idor_analyze_sql_core(query, dialect) {
        Ok(results) => serde_json::to_string(&results)
            .unwrap_or_else(|e| format!(r#"{{"error":"{}"}}"#, e)),
        Err(e) => format!(r#"{{"error":"{}"}}"#, e),
    })
    .unwrap_or_else(|_| r#"{"error":"Internal error"}"#.to_string())
}

#[pymodule]
fn zen_internals(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(detect_sql_injection, m)?)?;
    m.add_function(wrap_pyfunction!(idor_analyze_sql, m)?)?;
    Ok(())
}
