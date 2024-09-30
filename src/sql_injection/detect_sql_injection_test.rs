macro_rules! is_injection {
    ($query:expr, $input:expr) => {
        assert!(detect_sql_injection_str($query, $input, 0))
    };
}
macro_rules! not_is_injection {
    ($query:expr, $input:expr) => {
        assert!(!detect_sql_injection_str($query, $input, 0))
    };
}
#[cfg(test)]
mod tests {
    use crate::sql_injection::detect_sql_injection::detect_sql_injection_str;

    #[test]
    fn test_injection_with_token_counts() {
        is_injection!(
            "INSERT INTO users (name, age, email, city) VALUES ('Alice');;;;;;;    -- ', 30, 'alice@example.com', 'Wonderland'); -- Hellow",
            "Alice');;;;;;;    --"
        );
        is_injection!(
            "INSERT INTO users (name, age, email, city) VALUES ('Alice');;;;;;;  -- ', 30, 'alice@example.com', 'Wonderland');",
            "Alice');;;;;;;  --"
        );
    }

    #[test]
    fn test_encapsulated_strings() {
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "Alice"
        );
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "Bob"
        );
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('W.Al294*is', 'Bob')",
            "W.Al294*is"
        );
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('John', 'Doe')",
            "'John'"
        );

        is_injection!(
            "INSERT INTO users (name, surname) VALUES ('John', 'Doe')",
            "John', 'Doe"
        );
        is_injection!(
            "INSERT INTO users (name, surname) VALUES ('John', 'Doe')",
            "John',"
        );
        // MySQL Specific : 
        assert!(!detect_sql_injection_str(
            "INSERT INTO `users` (name, surname) VALUES ('John', 'Doe')", "`users`", 8));
        assert!(detect_sql_injection_str(
            "INSERT INTO `users` (name, surname) VALUES ('John', 'Doe')", "INTO `users`", 8));
        assert!(!detect_sql_injection_str("SELECT * FROM `comm` ents", "`comm`", 8));
        assert!(detect_sql_injection_str("SELECT * FROM `comm` ents", "`comm` ents", 8));
        assert!(detect_sql_injection_str("SELECT * FROM `comm` ", "FROM `comm`", 8));


    }

    #[test]
    fn test_keywords() {
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "INSERT"
        );
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "INS"
        );
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "users"
        );
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "VALUES"
        );

        is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "INSERT INTO"
        );
        is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "INSERT INTO users"
        );
        is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "INTO users"
        );
    }
    #[test]

    fn test_spaces_are_trimmed_from_input() {
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "VALUES "
        );
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            " INTO"
        );
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            " surname"
        );
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            " VALUES "
        );
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "          VALUES             "
        )
    }

    #[test]
    fn test_character_combos() {
        is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "('"
        );

        // one character, after spaces removed cannot be injection :
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            ", "
        );
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')          ;          ",
            "          ;          "
        );
        not_is_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')          6          ",
            "          6          "
        );

        not_is_injection!(
            "INSERT  INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "  "
        );
        not_is_injection!(
            "INSERT  INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "                 "
        );
    }

    #[test]
    fn test_auto_concat_strs() {
        not_is_injection!("SELECT * FROM 'abc' 'abc'", "abc");
        not_is_injection!("SELECT * FROM 'abc' 'abc'", "'abc'");
        not_is_injection!("SELECT * FROM 'abc' 'def'", "abc");

        is_injection!("SELECT * FROM 'abc' 'ebc' 'def'", "abc' 'ebc");
        is_injection!("SELECT * FROM 'abc' 'abc' 'abc'", "abc' 'abc");
    }

    #[test]
    fn test_nokeyword_exemption() {
        is_injection!("SELECT * FROM hakuna matata", "hakuna matata");
        not_is_injection!("SELECT * FROM hakuna matata", "hakuna ");
        not_is_injection!("SELECT * FROM hakuna matata", "una ");

        is_injection!(
            "SELECT * FROM hakuna matata theory",
            " hakuna matata theory"
        );
        is_injection!("SELECT * FROM hakuna matata theory", " kuna matata theo");

        is_injection!("SELECT * FROM hakuna matata", "FROM h");
        is_injection!("SELECT * FROM hakuna matata", "FROM hakuna");
        is_injection!("SELECT * FROM hakuna matata", "FROM hakuna matata");
        not_is_injection!(
            "SELECT * FROM \"table_name\" WHERE comment = \"I\" \"m writting you\"",
            "\"table_name\" "
        )
    }

    #[test]
    fn test_escape_sequences() {
        not_is_injection!("SELECT * FROM users WHERE id = 'users\\\\'", "users\\\\")
    }
}
