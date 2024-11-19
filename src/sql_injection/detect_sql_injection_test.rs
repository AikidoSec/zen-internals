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
macro_rules! not_injection {
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

    fn dialect(s: &str) -> i32 {
        match s {
            "mysql" => 8,
            "postgresql" => 9,
            "sqlite" => 12,
            _ => panic!("Unknown dialect"),
        }
    }

    #[test]
    fn test_postgres_dollar_signs() {
        not_injection!(
            "SELECT * FROM users WHERE id = $$' OR 1=1 -- $$",
            "' OR 1=1 -- "
        );
        not_injection!(
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
        not_injection!(
            "SELECT * FROM users WHERE id = $name$' OR 1=1 -- $name$",
            "' OR 1=1 -- "
        );
        not_injection!(
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
        not_injection!(
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
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "Alice"
        );
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "Bob"
        );
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('W.Al294*is', 'Bob')",
            "W.Al294*is"
        );
        not_injection!(
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
        not_injection!(
            "INSERT INTO `users` (name, surname) VALUES ('John', 'Doe')",
            "`users`",
            8
        );
        is_injection!(
            "INSERT INTO `users` (name, surname) VALUES ('John', 'Doe')",
            "INTO `users`",
            8
        );
        not_injection!("SELECT * FROM `comm` ents", "`comm`", 8);
        is_injection!("SELECT * FROM `comm` ents", "`comm` ents", 8);
        is_injection!("SELECT * FROM `comm` ", "FROM `comm`", 8);
    }

    #[test]
    fn test_keywords() {
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "INSERT"
        );
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "INS"
        );
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "users"
        );
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "VALUES"
        );

        not_injection!(
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
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "VALUES "
        );
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            " INTO"
        );
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            " surname"
        );
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            " VALUES "
        );
        not_injection!(
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
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')",
            ", "
        );
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')          ;          ",
            "          ;          "
        );
        not_injection!(
            "INSERT INTO users (name, surname) VALUES ('Alice', 'Bob')          6          ",
            "          6          "
        );

        not_injection!(
            "INSERT  INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "  "
        );
        not_injection!(
            "INSERT  INTO users (name, surname) VALUES ('Alice', 'Bob')",
            "                 "
        );
    }

    #[test]
    fn test_auto_concat_strs() {
        not_injection!("SELECT * FROM 'abc' 'abc'", "abc");
        not_injection!("SELECT * FROM 'abc' 'abc'", "'abc'");
        not_injection!("SELECT * FROM 'abc' 'def'", "abc");

        is_injection!("SELECT * FROM 'abc' 'ebc' 'def'", "abc' 'ebc");
        is_injection!("SELECT * FROM 'abc' 'abc' 'abc'", "abc' 'abc");
    }

    #[test]
    fn test_nokeyword_exemption() {
        is_injection!("SELECT * FROM hakuna matata", "hakuna matata");
        not_injection!("SELECT * FROM hakuna matata", "hakuna ");
        not_injection!("SELECT * FROM hakuna matata", "una ");

        is_injection!(
            "SELECT * FROM hakuna matata theory",
            " hakuna matata theory"
        );
        is_injection!("SELECT * FROM hakuna matata theory", "kuna matata theo");

        is_injection!("SELECT * FROM hakuna matata", "FROM h");
        is_injection!("SELECT * FROM hakuna matata", "FROM hakuna");
        is_injection!("SELECT * FROM hakuna matata", "FROM hakuna matata");
        not_injection!(
            "SELECT * FROM \"table_name\" WHERE comment = \"I\" \"m writting you\"",
            "\"table_name\" "
        )
    }

    #[test]
    fn test_if_query_does_not_contain_user_input() {
        not_injection!("SELECT * FROM users WHERE id = 1", "id = 'something else'");
    }

    #[test]
    fn test_escape_sequences() {
        not_injection!("SELECT * FROM users WHERE id = 'users\\\\'", "users\\\\")
    }

    #[test]
    fn test_multiple_string_characters() {
        // Query 1 testing : INSERT INTO books (title, description) VALUES ('${title}', "Description set by the user: '${description}'")
        not_injection!(
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
        not_injection!(
            "SELECT * FROM users WHERE email = 'user@example.com';",
            "SELECT *"
        );
        not_injection!(
            "INSERT INTO orders (user_id, product_id, quantity) VALUES (1, 2, 3);",
            "INSERT INTO"
        );
        not_injection!(
            "SELECT users.first_name, users.last_name, orders.order_id
             FROM users
             INNER JOIN orders ON users.id = orders.user_id
             WHERE orders.status = 'completed'",
            "INNER JOIN"
        );
        not_injection!(
            "SELECT users.first_name, users.last_name, orders.order_id
             FROM users
             LEFT JOIN orders ON users.id = orders.user_id;",
            "LEFT JOIN"
        );
        not_injection!(
            "SELECT orders.order_id, users.first_name, users.last_name
             FROM orders
             RIGHT JOIN users ON orders.user_id = users.id;",
            "RIGHT JOIN"
        );
        not_injection!(
            "SELECT users.first_name, users.last_name, orders.order_id
             FROM users
             LEFT OUTER JOIN orders ON users.id = orders.user_id;",
            "LEFT OUTER JOIN"
        );
        not_injection!(
            "SELECT orders.order_id, users.first_name, users.last_name
             FROM orders
             RIGHT OUTER JOIN users ON orders.user_id = users.id;",
            "RIGHT OUTER JOIN"
        );
        not_injection!(
            "DELETE FROM sessions WHERE session_id = 'xyz123'",
            "DELETE FROM"
        );
        not_injection!(
            "SELECT first_name, last_name, created_at
             FROM users
             ORDER BY created_at DESC;",
            "ORDER BY"
        );
        not_injection!(
            "SELECT category_id, COUNT(*) AS total_products
             FROM products
             GROUP BY category_id;",
            "GROUP BY"
        );
        not_injection!(
            "SELECT category_id, COUNT(*) AS total_products
             FROM products
             GROUP BY category_id;",
            "group BY"
        );
        not_injection!(
            "SELECT category_id, COUNT(*) AS total_products
             FROM products
             group by category_id;",
            "GROUP BY"
        );
        not_injection!(
            "INSERT INTO wishlists (user_id, product_id) VALUES (1, 3) ON CONFLICT (user_id, product_id) DO NOTHING",
            "ON CONFLICT"
        );
        not_injection!(
            "INSERT INTO users (id, email, login_count)
             VALUES (1, 'user@example.com', 1)
             ON CONFLICT (id)
             DO UPDATE SET login_count = users.login_count + 1;",
            "DO UPDATE"
        );
        not_injection!(
            "INSERT INTO wishlists (user_id, product_id) VALUES (1, 3) ON CONFLICT (user_id, product_id) DO NOTHING",
            "DO NOTHING"
        );
        not_injection!(
            "INSERT INTO users (id, email)
             VALUES (1, 'user@example.com')
             ON DUPLICATE KEY UPDATE email = 'user@example.com';",
            "ON DUPLICATE KEY UPDATE"
        );
        not_injection!(
            "SELECT COUNT(*) FROM users WHERE status = 'active';",
            "SELECT COUNT(*)"
        );
        not_injection!(
            "SELECT COUNT(*) FROM users WHERE status = 'active';",
            "COUNT(*)"
        );
        not_injection!("SELECT * FROM orders WHERE shipped_at IS NULL;", "IS NULL");
        not_injection!(
            "SELECT * FROM orders WHERE shipped_at IS NOT NULL;",
            "IS NOT NULL"
        );
        not_injection!(
            "SELECT * FROM users WHERE NOT EXISTS (SELECT 1 FROM orders WHERE users.id = orders.user_id);",
            "NOT EXISTS"
        );
        not_injection!(
            "SELECT DISTINCT ON (email) email, first_name, last_name
             FROM users
             ORDER BY email, created_at DESC;",
            "DISTINCT ON"
        );
    }

    #[test]
    fn test_common_sql_patterns_are_not_flagged() {
        not_injection!("SELECT * FROM users ORDER BY name ASC", "name ASC");
        not_injection!("SELECT * FROM users ORDER BY name DESC", "name DESC");
        not_injection!(
            "SELECT * FROM users ORDER BY created_at ASC",
            "created_at ASC"
        );
        not_injection!(
            "SELECT * FROM users ORDER BY created_at DESC",
            "created_at DESC"
        );
        not_injection!(
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

    #[test]
    fn test_postgres_backslash_escaping() {
        is_injection!(
            r#"SELECT * FROM users WHERE id = '\'OR 1=1--'"#,
            "'OR 1=1--",
            dialect("postgresql")
        );
        not_injection!(
            r#"SELECT * FROM users WHERE id = E'\'OR 1=1--'"#,
            "'OR 1=1--",
            dialect("postgresql")
        );
    }

    #[test]
    fn test_user_input_appears_as_column_name() {
        let query = r#"
            SELECT views.id AS view_id, view_settings.user_id, view_settings.settings
            FROM views
            INNER JOIN view_settings ON views.id = view_settings.view_id AND view_settings.user_id = ?
            WHERE views.business_id = ?
        "#;

        not_injection!(query, "views.id");
        not_injection!(query, "view_settings.user_id");

        is_injection!(query, "= view_settings.view_id");
    }

    #[test]
    fn test_function_calls() {
        is_injection!(
            "SELECT * FROM users WHERE id = 187 AND VERSION()",
            "187 AND VERSION()"
        );
        not_injection!(
            "SELECT * FROM users WHERE id = '187 AND VERSION()'",
            "187 AND VERSION()"
        );
    }

    #[test]
    fn test_sleep() {
        is_injection!(
            "SELECT * FROM users WHERE id = 187 AND SLEEP(5)",
            "187 AND SLEEP(5)"
        );
        not_injection!(
            "SELECT * FROM users WHERE id = '187 AND SLEEP(5)'",
            "187 AND SLEEP(5)"
        );
        is_injection!(
            "SELECT * FROM users WHERE id=984 AND IF(SUBSTRING(version(),1,1)=5,SLEEP(10),null)",
            "984 AND IF(SUBSTRING(version(),1,1)=5,SLEEP(10),null)"
        );
    }

    #[test]
    fn test_single_line_comments() {
        is_injection!(
            "SELECT * FROM users WHERE id = '1' OR 1=1 # '",
            "1' OR 1=1 # ",
            dialect("mysql")
        );
        not_injection!(
            "SELECT * FROM users WHERE id = '1'' OR 1=1 # '",
            "1' OR 1=1 # ",
            dialect("mysql")
        );
    }

    #[test]
    fn test_with_sqlite_placeholders() {
        // See https://github.com/WiseLibs/better-sqlite3/blob/master/docs/api.md#transactionfunction---function
        is_injection!(
            "INSERT INTO cats (name, age) VALUES (@name, @age)",
            "(@name, @age)",
            dialect("sqlite")
        );
    }

    #[test]
    fn test_with_pdo_placeholders() {
        // See https://www.php.net/manual/en/pdo.prepare.php
        is_injection!(
            "INSERT INTO cats (name, age) VALUES (:name, :age)",
            "(:name, :age)",
            dialect("mysql")
        );
        is_injection!(
            "INSERT INTO cats (name, age) VALUES (:name, :age)",
            "(:name, :age)",
            dialect("postgresql")
        );
    }

    #[test]
    fn test_with_percent_placeholders() {
        // See https://www.psycopg.org/docs/usage.html#passing-parameters-to-sql-queries
        is_injection!(
            "INSERT INTO cats (name, age) VALUES (%s, %s)",
            "(%s, %s)",
            dialect("postgresql")
        );
    }

    #[test]
    fn test_with_dollar_placeholders() {
        // See https://node-postgres.com/features/queries#parameterized-query
        is_injection!(
            "INSERT INTO cats (name, age) VALUES ($1, $2)",
            "($1, $2)",
            dialect("postgresql")
        );
    }

    #[test]
    fn test_with_pg_promise_placeholders() {
        // See https://github.com/vitaly-t/pg-promise?tab=readme-ov-file#named-parameters
        is_injection!(
            "INSERT INTO cats (name, age) VALUES (${name}, ${age})",
            "(${name}, ${age})",
            dialect("postgresql")
        );
    }

    #[test]
    fn test_does_not_flag_input_in_comments() {
        not_injection!("SELECT 1 -- some/input", "some/input");
        not_injection!("SELECT 1 /* some/input */", "some/input");
        // # comments are not supported by generic dialect
        not_injection!("SELECT 1 # some/input", "some/input", dialect("mysql"));
        not_injection!(
            r#"
                SELECT 1 AS one
                FROM "namespaces"
                INNER JOIN "members"
                ON "namespaces"."id" = "members"."source_id"
                WHERE "members"."type" = 'GroupMember'
                AND "members"."source_type" = 'Namespace'
                AND "namespaces"."type" = 'Group'
                AND "members"."user_id" = 1
                AND "members"."requested_at" IS NULL
                AND (access_level >= 10)
                LIMIT 1
                /*application:web,correlation_id:01JD0F3EJ9C6G9ZZED0D4834EV,endpoint_id:Dashboard::GroupsController#index,db_config_database:gitlabhq_development,db_config_name:main,line:/app/views/dashboard/groups/index.html.haml:5:in `_app_views_dashboard_groups_index_html_haml__4608572397795655832_591200'*/
           "#,
            "dashboard/groups"
        );
    }

    #[test]
    fn test_it_does_not_flag_input_in_multiple_safe_places() {
        not_injection!("SELECT 'some/input' -- some/input", "some/input");
        not_injection!("SELECT 'some/input' /* some/input */", "some/input");
        // # comments are not supported by generic dialect
        not_injection!(
            "SELECT 'some/input' # some/input",
            "some/input",
            dialect("mysql")
        );
    }

    #[test]
    fn test_it_does_flag_input_comments() {
        is_injection!("SELECT 1 -- some/input", "1 -- some/input");
        is_injection!("SELECT 1 /* some/input */", "1 /* some/input */");
        // # comments are not supported by generic dialect
        is_injection!("SELECT 1 # some/input", "1 # some/input", dialect("mysql"));
    }

    #[test]
    fn test_it_does_flag_input_in_multiple_places() {
        is_injection!(
            "SELECT '1 -- some/input', 1 -- some/input",
            "1 -- some/input"
        );
        is_injection!(
            "SELECT '1 /* some/input */', 1 /* some/input */",
            "1 /* some/input */"
        );
        // # comments are not supported by generic dialect
        is_injection!(
            "SELECT '1 # some/input', 1 # some/input",
            "1 # some/input",
            dialect("mysql")
        );
    }
}
