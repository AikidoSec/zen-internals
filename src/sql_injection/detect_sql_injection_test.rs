#[cfg(test)]
mod tests {
    use crate::sql_injection::detect_sql_injection::detect_sql_injection_str;
    #[test]
    fn test_escaping_strings() {
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, age, email, city) VALUES ('Alice');;;;;;;    -- ', 30, 'alice@example.com', 'Wonderland'); -- Hellow"
            ,
            "Alice');;;;;;;    --", 0));
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, age, email, city) VALUES ('Alice');;;;;;;  -- ', 30, 'alice@example.com', 'Wonderland');",
            "Alice');;;;;;;  --", 0));
    }
}
