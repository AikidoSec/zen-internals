#[cfg(test)]
mod tests {
    use crate::sql_injection::detect_sql_injection::detect_sql_injection_str;
    #[test]
    fn test_injection_with_token_counts() {
        // SQL Injection :
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, age, email, city) VALUES ('Alice');;;;;;;    -- ', 30, 'alice@example.com', 'Wonderland'); -- Hellow",
            "Alice');;;;;;;    --", 0));
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, age, email, city) VALUES ('Alice');;;;;;;  -- ', 30, 'alice@example.com', 'Wonderland');",
            "Alice');;;;;;;  --", 0));
    }

    #[test]
    fn test_encapsulated_strings() {
        // Not a SQL Injection :
        assert!(!detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "Alice",
            0
        ));
        assert!(!detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "Bob",
            0
        ));
        assert!(!detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('W.Al294*is', 'Bob')",
            "W.Al294*is",
            0
        ));
        assert!(!detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('John', 'Doe')",
            "'John'",
            0
        ));

        // SQL Injection :
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('John', 'Doe')",
            "John', 'Doe",
            0
        ));
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('John', 'Doe')",
            "John',",
            0
        ));
    }

    #[test]
    fn test_keywords() {
        // Not a SQL Injection :
        assert!(!detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "INSERT",
            0
        ));
        assert!(!detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "INS",
            0
        ));
        assert!(!detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "users",
            0
        ));
        assert!(!detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "VALUES",
            0
        ));

        // SQL Injection :
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "INSERT INTO",
            0
        ));
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "INSERT INTO users",
            0
        ));
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "INTO users",
            0
        ));
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "VALUES ",
            0
        ));
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            " INTO",
            0
        ));
    }
    #[test]
    fn test_character_combos() {
        // SQL Injection :
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "('",
            0
        ));
        assert!(detect_sql_injection_str(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            ", ",
            0
        ));
        assert!(detect_sql_injection_str(
            "INSERT  INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "  ",
            0
        ));
    }
}
