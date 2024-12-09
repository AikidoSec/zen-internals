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

#[cfg(test)]
mod tests {
    use crate::js_injection::is_safe_js_input::is_safe_js_input;
    use oxc::allocator::Allocator;
    use oxc::span::SourceType;

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
    }

    #[test]
    fn test_unsafe_js_input() {
        let allocator = Allocator::default();
        let source_type: SourceType = SourceType::unambiguous();

        is_unsafe!("globalThis.test()", &allocator, source_type);
        is_unsafe!("console.log('test')", &allocator, source_type);
        is_unsafe!("alert('test')", &allocator, source_type);
        is_unsafe!("const x = 1", &allocator, source_type);
        is_unsafe!("test()", &allocator, source_type);
        is_unsafe!("'test'", &allocator, source_type);
        is_unsafe!("'test' + 'test'", &allocator, source_type);
        is_unsafe!("'; //", &allocator, source_type);
        is_unsafe!("// test", &allocator, source_type);
        is_unsafe!("/* test */", &allocator, source_type);
        is_unsafe!("1 + 2; // test", &allocator, source_type);
        is_unsafe!("1 + 2; /* test */", &allocator, source_type);
        is_unsafe!("1 == true", &allocator, source_type);
        is_unsafe!("== true", &allocator, source_type);
        is_unsafe!("!!''", &allocator, source_type);
        is_unsafe!("[1, 2, 3]", &allocator, source_type);
        is_unsafe!("({ x: 1, y: 2 })", &allocator, source_type);
        is_unsafe!("function test() { return 1; }", &allocator, source_type);
        is_unsafe!("class Test { constructor() {} }", &allocator, source_type);
        is_unsafe!("new Test()", &allocator, source_type);
        is_unsafe!("'use strict';", &allocator, source_type);
        is_unsafe!("process.env", &allocator, source_type);
    }
}
