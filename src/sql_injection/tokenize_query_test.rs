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

    // Add more tests for different SQL queries and dialects as needed
}
