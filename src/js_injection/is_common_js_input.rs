use regex::Regex;

pub fn is_common_js_input(user_input: &str) -> bool {
    // Allow simple math operations
    let is_math: Regex = Regex::new(r"^[\d.,+\-*/%^\s]+$").unwrap();

    return is_math.is_match(user_input);
}
