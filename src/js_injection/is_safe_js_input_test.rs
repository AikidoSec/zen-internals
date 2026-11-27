#[cfg(test)]
mod tests {
    use crate::js_injection::is_safe_js_input::is_safe_js_input;
    use oxc::allocator::Allocator;
    use oxc::span::SourceType;

    macro_rules! is_safe {
        ($input:expr, $allocator:expr, $sourcetype:expr) => {
            assert!(is_safe_js_input($input, $allocator, $sourcetype))
        };
    }

    macro_rules! is_unsafe {
        ($input:expr, $allocator:expr, $sourcetype:expr) => {
            assert!(!is_safe_js_input($input, $allocator, $sourcetype))
        };
    }

}
