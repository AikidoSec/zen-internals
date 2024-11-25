macro_rules! is_injection {
    ($code:expr, $input:expr, $sourcetype:expr) => {
        assert!(detect_js_injection_str(
            &$code.to_lowercase(),
            &$input.to_lowercase(),
            $sourcetype
        ))
    };
}
macro_rules! not_injection {
    ($code:expr, $input:expr, $sourcetype:expr) => {
        assert!(!detect_js_injection_str(
            &$code.to_lowercase(),
            &$input.to_lowercase(),
            $sourcetype
        ))
    };
}
#[cfg(test)]
mod tests {
    use crate::js_injection::detect_js_injection::detect_js_injection_str;

    #[test]
    fn test_cjs_const() {
        not_injection!("const test = 'Hello World!';", "Hello World!", 0);
        is_injection!("const test = 'Hello World!'; //';", "Hello World!'; //", 0);
        is_injection!(
            "const test = 'Hello World!';console.log('Injected!'); //';",
            "Hello World!';console.log('Injected!'); //",
            0
        );
        is_injection!(
            "const test = 'Hello World!'; console.log('injection'); // This is a comment'; // Test",
            "Hello World!'; console.log('injection'); // This is a comment",
            0
        );
        is_injection!(
            "const test = 'Hello World!'; // This is a comment'; // Test",
            "Hello World!'; // This is a comment",
            0
        );
    }

    #[test]
    fn test_cjs_if() {
        not_injection!("if (true) { return true; }", "true", 0);
        not_injection!("if (1 > 5) { return true; }", "5", 0);
        is_injection!(
            "if(username === 'admin' || 1 === 1) { return true; } //');",
            "admin' || 1 === 1) { return true; } //",
            0
        );
        not_injection!(
            "if(username === 'admin' || 1 === 1) { return true; }",
            "admin",
            0
        );
        is_injection!(
            "if (username === 'admin' || 1 === 1) { return true; } //') {}",
            "admin' || 1 === 1) { return true; } //",
            0
        );
        is_injection!("if (1 > 5 || 1 === 1) { return true; }", "5 || 1 === 1", 0);
    }

    #[test]

    fn mongodb_js() {
        not_injection!("this.name === 'a' && sleep(2000) && 'b'", "a", 0);
        not_injection!("this.group === 1", "1", 0);
        is_injection!(
            "this.name === 'a' && sleep(2000) && 'b'",
            "a' && sleep(2000) && 'b",
            0
        );
        is_injection!("const test = this.group === 1 || 1 === 1;", "1 || 1 ===", 0);
    }

    #[test]
    fn test_cjs_function() {
        not_injection!("function test() { return 'Hello'; }", "Hello", 0);
        not_injection!("test(\"arg1\", 0, true);", "arg1", 0);
        is_injection!(
            "function test() { return 'Hello'; } //';}",
            "Hello'; } //",
            0
        );
        is_injection!(
            "test(\"arg1\", 12, true); // \", 0, true);",
            "arg1\", 12, true); // ",
            0
        );
    }

    #[test]
    fn test_no_js_injection() {
        not_injection!("Hello World!", "Hello World!", 0);
        not_injection!("", "", 0);
        not_injection!("", "Hello World!", 0);
        not_injection!("Hello World!", "", 0);
        not_injection!("const test = 123;", "123", 0);
        not_injection!("// Reason: Test", "Test", 0);
    }
}
