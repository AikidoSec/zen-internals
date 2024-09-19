#[cfg(test)]
mod tests {
    use crate::shell_injection::is_safely_encapsulated::is_safely_encapsulated;
    use std::assert_eq;

    #[test]
    fn test_safe_between_single_quotes() {
        assert_eq!(is_safely_encapsulated("echo '$USER'", "$USER"), true);
        assert_eq!(is_safely_encapsulated("echo '`$USER'", "`USER"), true);
    }
    #[test]
    fn test_single_quote_in_single_quotes() {
        assert_eq!(is_safely_encapsulated("echo ''USER'", "'USER"), false);
    }
    #[test]
    fn test_dangerous_chars_between_double_quotes() {
        assert_eq!(is_safely_encapsulated("echo \"=USER\"", "=USER"), true);
        assert_eq!(is_safely_encapsulated("echo \"$USER\"", "$USER"), false);
        assert_eq!(is_safely_encapsulated("echo \"!USER\"", "!USER"), false);
        assert_eq!(is_safely_encapsulated("echo \"\\`USER\"", "`USER"), false);
        assert_eq!(is_safely_encapsulated("echo \"\\USER\"", "\\USER"), false);
    }
    #[test]
    fn test_same_user_input_multiple_times() {
        assert_eq!(is_safely_encapsulated("echo '$USER' '$USER'", "$USER"), true);
        assert_eq!(is_safely_encapsulated("echo \"$USER\" '$USER'", "$USER"), false);
        assert_eq!(is_safely_encapsulated("echo \"$USER\" \"$USER\"", "$USER"), false);
    }

    #[test]
    fn test_first_and_last_quote_does_not_match() {
        assert_eq!(is_safely_encapsulated("echo '$USER\"", "$USER"), false);
        assert_eq!(is_safely_encapsulated("echo \"$USER'", "$USER"), false);
    }

    #[test]
    fn test_first_or_last_character_not_escape_char() {
        assert_eq!(is_safely_encapsulated("echo $USER'", "$USER"), false);
        assert_eq!(is_safely_encapsulated("echo $USER\"", "$USER"), false);
    }
    #[test]
    fn test_user_input_does_not_occur_in_command() {
        assert_eq!(is_safely_encapsulated("echo 'USER'", "$USER"), true);
        assert_eq!(is_safely_encapsulated("echo \"USER\"", "$USER"), true);
    }
}
