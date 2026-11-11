#[cfg(test)]
mod tests {
    use crate::js_injection::is_safe_js_input::is_safe_js_input;

    macro_rules! is_safe {
        ($input:expr) => {
            assert!(is_safe_js_input($input, 0), "{:?}", $input)
        };
    }

    macro_rules! is_unsafe {
        ($input:expr) => {
            assert!(!is_safe_js_input($input, 0), "{:?}", $input)
        };
    }

    #[test]
    fn test_safe_js_input() {
        is_safe!("1 + 2");
        is_safe!("1 - 2");
        is_safe!("1 * 2");
        is_safe!("1 / 2");
        is_safe!("1 ** 2");
        is_safe!("1 % 2");
        is_safe!("1 + 2 * 3");
        is_safe!("(1 + 2) * 3");
        is_safe!("1e3 + 2e3");
        is_safe!("1, 2");
        // Unary plus/minus on numbers
        is_safe!("-10");
        is_safe!("+5");
        is_safe!("-3.14");
        is_safe!("-1e3");
        is_safe!("1 + -2");
        is_safe!("-(1 + 2)");
        is_safe!("- -10");
        is_safe!("true");
        is_safe!("false");
        is_safe!("null");
        is_safe!(" true ");
    }

    #[test]
    fn test_unsafe_js_input() {
        is_unsafe!("globalThis.test()");
        is_unsafe!("console.log('test')");
        is_unsafe!("alert('test')");
        is_unsafe!("const x = 1");
        is_unsafe!("test()");
        is_unsafe!("'test'");
        is_unsafe!("'test' + 'test'");
        is_unsafe!("'; //");
        is_unsafe!("// test");
        is_unsafe!("/* test */");
        is_unsafe!("1 + 2; // test");
        is_unsafe!("1 + 2; /* test */");
        is_unsafe!("1 == true");
        is_unsafe!("== true");
        is_unsafe!("!!''");
        is_unsafe!("[1, 2, 3]");
        is_unsafe!("({ x: 1, y: 2 })");
        is_unsafe!("function test() { return 1; }");
        is_unsafe!("class Test { constructor() {} }");
        is_unsafe!("new Test()");
        is_unsafe!("'use strict';");
        is_unsafe!("process.env");
        // Unsafe unary operators
        is_unsafe!("!x");
        is_unsafe!("~10");
        is_unsafe!("typeof x");
        is_unsafe!("void 0");
        is_unsafe!("delete obj.x");
        // Safe unary operator but unsafe operand
        is_unsafe!("-x");
        is_unsafe!("-alert()");
        is_unsafe!("-process.env");
    }

    #[test]
    fn test_arithmetic_token_boundaries() {
        for (input, expected) in [
            ("1 + +2", true),
            ("1 - -2", true),
            ("++1", false),
            ("1++", false),
            ("-1 ** 2", false),
            ("(-1) ** 2", true),
            ("1 ** -2", true),
            ("1/* comment */+2", false),
            ("1//2", false),
            ("1n + 2n", false),
            ("1(2)", false),
            ("1 2", false),
            ("1\n2", true),
            ("1\u{a0}+\u{3000}2", true),
            ("1\u{2028}2", true),
            ("1\u{200b}+2", false),
            ("1;2;", true),
            ("1;;2", false),
            ("(1;2)", false),
            ("()1", false),
            ("(1", false),
            ("1)", false),
            ("1+", false),
            ("#!1\n2", false),
            ("\u{feff}#!1\n2", false),
        ] {
            assert_eq!(is_safe_js_input(input, 0), expected, "{input:?}");
        }
    }
}
