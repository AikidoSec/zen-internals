/* Zen Vulnerability library, contains Zen vulnerability code written in Rust and exported
 * Using FFI. Currently we support the following algorithms :
 * - JS Injection
 * - SQL Injection
 */
mod helpers;
mod shell_injection;

// FFI Bindings
pub mod ffi_bindings;

// Wasm bindings
mod wasm_bindings;

#[cfg(feature = "benchmarking")]
pub mod sql_injection;

#[cfg(not(feature = "benchmarking"))]
mod sql_injection;

#[cfg(feature = "benchmarking")]
pub mod js_injection;

#[cfg(not(feature = "benchmarking"))]
mod js_injection;
