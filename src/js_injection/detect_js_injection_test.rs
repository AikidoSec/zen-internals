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
            "const test = 'Hello World!'; // This is a comment'; // Test",
            "Hello World!'; // This is a comment",
            0
        );
    }

    #[test]
    fn test_cjs_if() {
        not_injection!("if (true) { return true; }", "true", 0);
        is_injection!(
            "if(username === 'admin' || 1 === 1) { return true; } //');",
            "admin' || 1 === 1) { return true; } //",
            0
        );
    }

    #[test]

    fn mongodb_js() {
        is_injection!(
            "this.name === 'a' && sleep(2000) && 'b'",
            "a' && sleep(2000) && 'b",
            0
        );
    }
}
