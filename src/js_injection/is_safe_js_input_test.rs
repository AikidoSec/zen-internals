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

    #[test]
    fn test_safe_js_input() {
        let allocator = Allocator::default();
        let source_type: SourceType = SourceType::unambiguous();

        is_safe!("1 + 2", &allocator, source_type);
        is_safe!("1 - 2", &allocator, source_type);
        is_safe!("1 * 2", &allocator, source_type);
        is_safe!("1 / 2", &allocator, source_type);
        is_safe!("1 ** 2", &allocator, source_type);
        is_safe!("1 % 2", &allocator, source_type);
        is_safe!("1 + 2 * 3", &allocator, source_type);
        is_safe!("(1 + 2) * 3", &allocator, source_type);
        is_safe!("1e3 + 2e3", &allocator, source_type);
        is_safe!("1, 2", &allocator, source_type);
        // Unary plus/minus on numbers
        is_safe!("-10", &allocator, source_type);
        is_safe!("+5", &allocator, source_type);
        is_safe!("-3.14", &allocator, source_type);
        is_safe!("-1e3", &allocator, source_type);
        is_safe!("1 + -2", &allocator, source_type);
        is_safe!("-(1 + 2)", &allocator, source_type);
        is_safe!("- -10", &allocator, source_type);
    }

}
