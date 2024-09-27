#[cfg(test)]
mod tests {
    use crate::sql_injection::tokenize_query::tokenize_query;
    use sqlparser::keywords::Keyword;
    use sqlparser::tokenizer::{Token, Whitespace, Word};

    #[test]
    fn test_tokenize_simple_select() {
        let sql = "SELECT * FROM users;";
        let dialect = 0; // Replace with the appropriate dialect enum value
        let tokens = tokenize_query(sql, dialect);

        let expected_tokens: Vec<Token> = vec![
            Token::Word(Word {
                value: "SELECT".to_string(),
                quote_style: None,
                keyword: Keyword::SELECT,
            }),
            Token::Whitespace(Whitespace::Space),
            Token::Mul,
            Token::Whitespace(Whitespace::Space),
            Token::Word(Word {
                value: "FROM".to_string(),
                quote_style: None,
                keyword: Keyword::FROM,
            }),
            Token::Whitespace(Whitespace::Space),
            Token::Word(Word {
                value: "users".to_string(),
                quote_style: None,
                keyword: Keyword::NoKeyword,
            }),
            Token::SemiColon,
        ];

        assert_eq!(tokens, expected_tokens);
    }

    #[test]
    fn test_tokenize_insert() {
        let sql = "INSERT INTO users (name, age) VALUES ('Alice', 30);";
        let dialect = 0; // Replace with the appropriate dialect enum value
        let tokens = tokenize_query(sql, dialect);

        let expected_tokens: Vec<Token> = vec![
            Token::Word(Word {
                value: "INSERT".to_string(),
                quote_style: None,
                keyword: Keyword::INSERT,
            }),
            Token::Whitespace(Whitespace::Space),
            Token::Word(Word {
                value: "INTO".to_string(),
                quote_style: None,
                keyword: Keyword::INTO,
            }),
            Token::Whitespace(Whitespace::Space),
            Token::Word(Word {
                value: "users".to_string(),
                quote_style: None,
                keyword: Keyword::NoKeyword,
            }),
            Token::Whitespace(Whitespace::Space),
            Token::LParen,
            Token::Word(Word {
                value: "name".to_string(),
                quote_style: None,
                keyword: Keyword::NAME,
            }),
            Token::Comma,
            Token::Whitespace(Whitespace::Space),
            Token::Word(Word {
                value: "age".to_string(),
                quote_style: None,
                keyword: Keyword::NoKeyword,
            }),
            Token::RParen,
            Token::Whitespace(Whitespace::Space),
            Token::Word(Word {
                value: "VALUES".to_string(),
                quote_style: None,
                keyword: Keyword::VALUES,
            }),
            Token::Whitespace(Whitespace::Space),
            Token::LParen,
            Token::SingleQuotedString("Alice".to_string()),
            Token::Comma,
            Token::Whitespace(Whitespace::Space),
            Token::Number("30".to_string(), false),
            Token::RParen,
            Token::SemiColon,
        ];

        assert_eq!(tokens, expected_tokens);
    }

    #[test]
    fn test_short_sql_with_singeline_comment() {
        let sql = "1=1 -- This is a lovely single line comment.";
        let dialect = 0; // Replace with the appropriate dialect enum value
        let tokens = tokenize_query(sql, dialect);

        let expected_tokens: Vec<Token> = vec![
            Token::Number("1".to_string(), false),
            Token::Eq,
            Token::Number("1".to_string(), false),
            Token::Whitespace(Whitespace::Space),
            Token::Whitespace(Whitespace::SingleLineComment {
                comment: " This is a lovely single line comment.".to_string(),
                prefix: "--".to_string(),
            }),
        ];
        assert_eq!(tokens, expected_tokens);
    }
    #[test]
    fn test_short_sql_with_multiline_comment() {
        let sql: &str = "1=1 /* Multiline Comment */";
        let dialect = 0; // Replace with the appropriate dialect enum value
        let tokens = tokenize_query(sql, dialect);

        let expected_tokens: Vec<Token> = vec![
            Token::Number("1".to_string(), false),
            Token::Eq,
            Token::Number("1".to_string(), false),
            Token::Whitespace(Whitespace::Space),
            Token::Whitespace(Whitespace::MultiLineComment(
                " Multiline Comment ".to_string(),
            )),
        ];
        assert_eq!(tokens, expected_tokens);
    }

    #[test]
    fn test_tokenize_error_handling() {
        let sql = "sdlerg F'RM %^"; // Malformed SQL
        let dialect = 0; // Replace with the appropriate dialect enum value
        let tokens = tokenize_query(sql, dialect);

        // Expecting an empty vector due to tokenization error
        assert!(tokens.is_empty());
    }

    // Add more tests for different SQL queries and dialects as needed
}
