macro_rules! is_injection {
    ($query:expr, $input:expr) => {
        assert!(detect_sql_injection_str(
            &$query.to_lowercase(),
            &$input.to_lowercase(),
            0
        ))
    };
    ($query:expr, $input:expr, $dialect:expr) => {
        assert!(detect_sql_injection_str(
            &$query.to_lowercase(),
            &$input.to_lowercase(),
            $dialect
        ))
    };
}
macro_rules! not_is_injection {
    ($query:expr, $input:expr) => {
        assert!(!detect_sql_injection_str(
            &$query.to_lowercase(),
            &$input.to_lowercase(),
            0
        ))
    };
    ($query:expr, $input:expr, $dialect:expr) => {
        assert!(!detect_sql_injection_str(
            &$query.to_lowercase(),
            &$input.to_lowercase(),
            $dialect
        ))
    };
}
#[cfg(test)]
mod tests {
    use crate::sql_injection::detect_sql_injection::detect_sql_injection_str;

    #[test]
    fn test_postgres_dollar_signs() {
        not_is_injection!(
            "SELECT * FROM users WHERE id = $$' OR 1=1 -- $$",
            "' OR 1=1 -- "
        );
        not_is_injection!(
            "SELECT * FROM users WHERE id = $$1; DROP TABLE users; -- $$",
            "1; DROP TABLE users; -- "
        );
        is_injection!(
            "SELECT * FROM users WHERE id = $$1$$ OR 1=1 -- $$",
            "1$$ OR 1=1 -- "
        );
    }

    #[test]
    fn test_postgres_dollar_named_dollar_signs() {
        not_is_injection!(
            "SELECT * FROM users WHERE id = $name$' OR 1=1 -- $name$",
            "' OR 1=1 -- "
        );
        not_is_injection!(
            "SELECT * FROM users WHERE id = $name$1; DROP TABLE users; -- $name$",
            "1; DROP TABLE users; -- "
        );
        is_injection!(
            "SELECT * FROM users WHERE id = $name$1$name$ OR 1=1 -- $name$",
            "1$name$ OR 1=1 -- "
        );
    }

    #[test]
    fn test_it_detects_injections() {
        is_injection!(
            "SELECT * FROM users WHERE id = '' OR 1=1 -- '",
            "' OR 1=1 --"
        );
        is_injection!(
            "SELECT * FROM users WHERE id = '1'; DROP TABLE users; -- '",
            "1'; DROP TABLE users; -- "
        );
        is_injection!("SELECT * FROM users WHERE id = 1 OR 1=1", "1 OR 1=1");
    }

    #[test]
    fn test_false_positives() {
        not_is_injection!(
            r#"SELECT * FROM users WHERE id = "' OR 1=1 -- ""#,
            "' OR 1=1 -- "
        );
    }

    #[test]
    fn test_parse_server_injection() {
        // https://pwn-la-chapelle.eu/posts/dhm2024_parsemypostgres/
        is_injection!(
            r#"SELECT * FROM "_User" WHERE "username" ~ 'A''B''';SELECT PG_SLEEP(3);--;' AND ("_rperm" IS NULL OR "_rperm" && ARRAY['*','*'])  LIMIT 100"#,
            "A''B''';SELECT PG_SLEEP(3);--"
        );
    }

    #[test]
    fn test_litellm() {
        // https://huntr.com/bounties/a4f6d357-5b44-4e00-9cac-f1cc351211d2
        is_injection!(
            r#"SELECT * FROM "LiteLLM_UserTable" WHERE "user_id" IN ('1', '') UNION SELECT '1', '','{}', '', NULL, 0, '', '{}', NULL, NULL, NULL, '', NULL, '{}', '{}', '{}' from pg_sleep(3)-- -')"#,
            r#"') UNION SELECT '1', '','{}', '', NULL, 0, '', '{}', NULL, NULL, NULL, '', NULL, '{}', '{}', '{}' from pg_sleep(3)-- -"#
        );
    }

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
        not_is_injection!(
            "INSERT INTO `users` (name, surname) VALUES ('John', 'Doe')",
            "`users`",
            8
        );
        is_injection!(
            "INSERT INTO `users` (name, surname) VALUES ('John', 'Doe')",
            "INTO `users`",
            8
        );
        not_is_injection!("SELECT * FROM `comm` ents", "`comm`", 8);
        is_injection!("SELECT * FROM `comm` ents", "`comm` ents", 8);
        is_injection!("SELECT * FROM `comm` ", "FROM `comm`", 8);
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

        not_is_injection!(
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
        is_injection!("SELECT * FROM hakuna matata theory", "kuna matata theo");

        is_injection!("SELECT * FROM hakuna matata", "FROM h");
        is_injection!("SELECT * FROM hakuna matata", "FROM hakuna");
        is_injection!("SELECT * FROM hakuna matata", "FROM hakuna matata");
        not_is_injection!(
            "SELECT * FROM \"table_name\" WHERE comment = \"I\" \"m writting you\"",
            "\"table_name\" "
        )
    }

    #[test]
    fn test_if_query_does_not_contain_user_input() {
        not_is_injection!("SELECT * FROM users WHERE id = 1", "id = 'something else'");
    }

    #[test]
    fn test_escape_sequences() {
        not_is_injection!("SELECT * FROM users WHERE id = 'users\\\\'", "users\\\\")
    }

    #[test]
    fn test_multiple_string_characters() {
        // Query 1 testing : INSERT INTO books (title, description) VALUES ('${title}', "Description set by the user: '${description}'")
        not_is_injection!(
            "INSERT INTO books (title, description) VALUES ('${title}', \"Description set by the user: ''), ('exploit',system_user());'\")",
        "'), ('exploit',system_user());");
        // Submission AIKIDO-OCRA7GFG :
        is_injection!(
            "INSERT INTO books (title, description) VALUES ('${title}', \"Description set by the user: '\"), (\"exploit\",system_user());--'\")",
            "\"), (\"exploit\",system_user());--"
        );
        is_injection!(
            "INSERT INTO books (title, description) VALUES ('${title}', \"Description set by the user: \"), (\"exploit\",system_user()))",
            "\"), (\"exploit\",system_user())"
        );
    }

    #[test]
    fn test_common_sql_combinations_are_not_flagged() {
        not_is_injection!(
            "SELECT * FROM users WHERE email = 'user@example.com';",
            "SELECT *"
        );
        not_is_injection!(
            "INSERT INTO orders (user_id, product_id, quantity) VALUES (1, 2, 3);",
            "INSERT INTO"
        );
        not_is_injection!(
            "SELECT users.first_name, users.last_name, orders.order_id
             FROM users
             INNER JOIN orders ON users.id = orders.user_id
             WHERE orders.status = 'completed'",
            "INNER JOIN"
        );
        not_is_injection!(
            "SELECT users.first_name, users.last_name, orders.order_id
             FROM users
             LEFT JOIN orders ON users.id = orders.user_id;",
            "LEFT JOIN"
        );
        not_is_injection!(
            "SELECT orders.order_id, users.first_name, users.last_name
             FROM orders
             RIGHT JOIN users ON orders.user_id = users.id;",
            "RIGHT JOIN"
        );
        not_is_injection!(
            "SELECT users.first_name, users.last_name, orders.order_id
             FROM users
             LEFT OUTER JOIN orders ON users.id = orders.user_id;",
            "LEFT OUTER JOIN"
        );
        not_is_injection!(
            "SELECT orders.order_id, users.first_name, users.last_name
             FROM orders
             RIGHT OUTER JOIN users ON orders.user_id = users.id;",
            "RIGHT OUTER JOIN"
        );
        not_is_injection!(
            "DELETE FROM sessions WHERE session_id = 'xyz123'",
            "DELETE FROM"
        );
        not_is_injection!(
            "SELECT first_name, last_name, created_at
             FROM users
             ORDER BY created_at DESC;",
            "ORDER BY"
        );
        not_is_injection!(
            "SELECT category_id, COUNT(*) AS total_products
             FROM products
             GROUP BY category_id;",
            "GROUP BY"
        );
        not_is_injection!(
            "SELECT category_id, COUNT(*) AS total_products
             FROM products
             GROUP BY category_id;",
            "group BY"
        );
        not_is_injection!(
            "SELECT category_id, COUNT(*) AS total_products
             FROM products
             group by category_id;",
            "GROUP BY"
        );
        not_is_injection!(
            "INSERT INTO wishlists (user_id, product_id) VALUES (1, 3) ON CONFLICT (user_id, product_id) DO NOTHING",
            "ON CONFLICT"
        );
        not_is_injection!(
            "INSERT INTO users (id, email, login_count)
             VALUES (1, 'user@example.com', 1)
             ON CONFLICT (id)
             DO UPDATE SET login_count = users.login_count + 1;",
            "DO UPDATE"
        );
        not_is_injection!(
            "INSERT INTO wishlists (user_id, product_id) VALUES (1, 3) ON CONFLICT (user_id, product_id) DO NOTHING",
            "DO NOTHING"
        );
        not_is_injection!(
            "INSERT INTO users (id, email)
             VALUES (1, 'user@example.com')
             ON DUPLICATE KEY UPDATE email = 'user@example.com';",
            "ON DUPLICATE KEY UPDATE"
        );
        not_is_injection!(
            "SELECT COUNT(*) FROM users WHERE status = 'active';",
            "SELECT COUNT(*)"
        );
        not_is_injection!(
            "SELECT COUNT(*) FROM users WHERE status = 'active';",
            "COUNT(*)"
        );
        not_is_injection!("SELECT * FROM orders WHERE shipped_at IS NULL;", "IS NULL");
        not_is_injection!(
            "SELECT * FROM orders WHERE shipped_at IS NOT NULL;",
            "IS NOT NULL"
        );
        not_is_injection!(
            "SELECT * FROM users WHERE NOT EXISTS (SELECT 1 FROM orders WHERE users.id = orders.user_id);",
            "NOT EXISTS"
        );
        not_is_injection!(
            "SELECT DISTINCT ON (email) email, first_name, last_name
             FROM users
             ORDER BY email, created_at DESC;",
            "DISTINCT ON"
        );
    }

    #[test]
    fn test_common_sql_patterns_are_not_flagged() {
        not_is_injection!("SELECT * FROM users ORDER BY name ASC", "name ASC");
        not_is_injection!("SELECT * FROM users ORDER BY name DESC", "name DESC");
        not_is_injection!(
            "SELECT * FROM users ORDER BY created_at ASC",
            "created_at ASC"
        );
        not_is_injection!(
            "SELECT * FROM users ORDER BY created_at DESC",
            "created_at DESC"
        );
        not_is_injection!(
            "select `recommendations`.*, (select count(*) from `recommendation_click_events` where `recommendation_click_events`.`recommendation_id` = recommendations.id) as `count__clicks`, (select count(*) from `recommendation_subscribe_events` where `recommendation_subscribe_events`.`recommendation_id` = recommendations.id) as `count__subscribers` from `recommendations` order by created_at desc limit ?",
            "created_at desc"
        );
    }

    #[test]
    fn test_it_still_flags_common_sql_patterns_with_more_stuff() {
        is_injection!(
          "select `recommendations`.*, (select count(*) from `recommendation_click_events` where `recommendation_click_events`.`recommendation_id` = recommendations.id) as `count__clicks`, (select count(*) from `recommendation_subscribe_events` where `recommendation_subscribe_events`.`recommendation_id` = recommendations.id) as `count__subscribers` from `recommendations` order by date DESC LIMIT 1",
          "date DESC LIMIT 1"
        );
        is_injection!(
          "select `recommendations`.*, (select count(*) from `recommendation_click_events` where `recommendation_click_events`.`recommendation_id` = recommendations.id) as `count__clicks`, (select count(*) from `recommendation_subscribe_events` where `recommendation_subscribe_events`.`recommendation_id` = recommendations.id) as `count__subscribers` from `recommendations` order by date DESC, id ASC limit 1",
          "date DESC, id ASC"
        );
    }
}
