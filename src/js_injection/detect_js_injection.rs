use super::have_tokens_changed::have_tokens_changed;
use super::is_safe_js_input::is_safe_js_input;
use super::tokenize_code::tokenize_code;

pub fn detect_js_injection_str(code: &str, userinput: &str, sourcetype: i32) -> bool {
    if userinput.len() <= 1 || userinput.len() > code.len() || !code.contains(userinput) {
        return false;
    }

    if is_safe_js_input(userinput, sourcetype) {
        return false;
    }

    let Some(tokens) = tokenize_code(code, sourcetype) else {
        return false;
    };

    let code_without_input = code.replace(userinput, &"a".repeat(userinput.len()));
    let Some(tokens_without_input) = tokenize_code(&code_without_input, sourcetype) else {
        return false;
    };

    // Invalid JavaScript can still contain an injection attempt, so compare recovered tokens too.
    have_tokens_changed(code, &tokens, &code_without_input, &tokens_without_input)
}
