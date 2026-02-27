/* Zen Vulnerability library, contains Zen vulnerability code written in Rust and exported
 * Using FFI. Currently we support the following algorithms :
 * - JS Injection
 * - SQL Injection
 */
mod helpers;

// FFI Bindings
#[cfg(not(feature = "wasm-js"))]
pub mod ffi_bindings;

// Wasm bindings
#[cfg(feature = "wasm-js")]
mod wasm_bindings;

// PyO3 Bindings
#[cfg(feature = "python")]
mod pyo3_bindings;

#[cfg(feature = "benchmarking")]
pub mod sql_injection;

#[cfg(not(feature = "benchmarking"))]
mod sql_injection;

#[cfg(feature = "benchmarking")]
pub mod js_injection;

#[cfg(not(feature = "benchmarking"))]
mod js_injection;

#[cfg(feature = "benchmarking")]
pub mod idor;

#[cfg(not(feature = "benchmarking"))]
mod idor;
