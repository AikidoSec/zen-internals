use std::collections::HashSet;

const LOWERCASE: &[char] = &[
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z',
];
const UPPERCASE: &[char] = &[
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S',
    'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
];
const NUMBERS: &[char] = &['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'];
const SPECIAL: &[char] = &['!', '#', '$', '%', '^', '&', '*', '|', ';', ':', '<', '>'];
const KNOWN_WORD_SEPARATORS: &[&str] = &["-"];
const WHITE_SPACE: char = ' ';
const MINIMUM_LENGTH: usize = 10;

pub fn looks_like_a_secret(s: &str) -> bool {
    if s.len() <= MINIMUM_LENGTH {
        return false;
    }

    let has_number = s.chars().any(|c| NUMBERS.contains(&c));
    if !has_number {
        return false;
    }

    let has_lower = s.chars().any(|c| LOWERCASE.contains(&c));
    let has_upper = s.chars().any(|c| UPPERCASE.contains(&c));
    let has_special = s.chars().any(|c| SPECIAL.contains(&c));
    let charsets = [has_lower, has_upper, has_special];

    if charsets.iter().filter(|&&x| x).count() < 2 {
        return false;
    }

    if s.contains(WHITE_SPACE) {
        return false;
    }

    if KNOWN_WORD_SEPARATORS.iter().any(|&sep| s.contains(sep)) {
        return false;
    }

    let window_size = MINIMUM_LENGTH;
    let mut ratios = Vec::new();
    for i in 0..=s.len() - window_size {
        let window = &s[i..i + window_size];
        let unique_chars: HashSet<char> = window.chars().collect();
        ratios.push(unique_chars.len() as f64 / window_size as f64);
    }

    let average_ratio: f64 = ratios.iter().sum::<f64>() / ratios.len() as f64;

    average_ratio > 0.75
}
