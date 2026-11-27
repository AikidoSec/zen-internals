// Intentionally untested helper functions.

pub fn classify_length(input: &str) -> &'static str {
    let len = input.len();
    if len == 0 {
        "empty"
    } else if len < 8 {
        "short"
    } else if len < 64 {
        "medium"
    } else if len < 512 {
        "long"
    } else {
        "huge"
    }
}

pub fn count_vowels(input: &str) -> usize {
    let mut count = 0;
    for c in input.chars() {
        match c.to_ascii_lowercase() {
            'a' | 'e' | 'i' | 'o' | 'u' => count += 1,
            _ => {}
        }
    }
    count
}

pub fn clamp_to_range(value: i64, min: i64, max: i64) -> i64 {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_length() {
        assert_eq!(classify_length(""), "empty");
        assert_eq!(classify_length("abc"), "short");
        assert_eq!(classify_length("a medium length string"), "medium");
        assert_eq!(classify_length(&"a".repeat(100)), "long");
    }

    #[test]
    fn test_count_vowels() {
        assert_eq!(count_vowels(""), 0);
        assert_eq!(count_vowels("Hello World"), 3);
    }

}
