#[cfg(test)]
mod tests {
    use crate::sql_injection::is_whitespace_token::is_whitespace_token;
    use sqlparser::ast::DollarQuotedString;
    use sqlparser::keywords::Keyword;
    use sqlparser::tokenizer::{Token, Whitespace, Word};

    #[test]
    fn test_string_types() {
        // Test various safe tokens
        assert!(!is_whitespace_token(&Token::SingleQuotedString(
            "test".to_string()
        )));
        assert!(!is_whitespace_token(&Token::DoubleQuotedString(
            "test".to_string()
        )));
        assert!(!is_whitespace_token(&Token::TripleSingleQuotedString(
            "test".to_string()
        )));
        assert!(!is_whitespace_token(&Token::TripleDoubleQuotedString(
            "test".to_string()
        )));
        assert!(!is_whitespace_token(&Token::DollarQuotedString(
            DollarQuotedString {
                value: "test".to_string(),
                tag: None,
            }
        )));
        assert!(!is_whitespace_token(&Token::SingleQuotedByteStringLiteral(
            "test".to_string()
        )));
        assert!(!is_whitespace_token(&Token::DoubleQuotedByteStringLiteral(
            "test".to_string()
        )));
        assert!(!is_whitespace_token(
            &Token::TripleSingleQuotedByteStringLiteral("test".to_string())
        ));
        assert!(!is_whitespace_token(
            &Token::TripleDoubleQuotedByteStringLiteral("test".to_string())
        ));
        assert!(!is_whitespace_token(&Token::SingleQuotedRawStringLiteral(
            "test".to_string()
        )));
        assert!(!is_whitespace_token(&Token::DoubleQuotedRawStringLiteral(
            "test".to_string()
        )));
        assert!(!is_whitespace_token(
            &Token::TripleSingleQuotedRawStringLiteral("test".to_string())
        ));
        assert!(!is_whitespace_token(
            &Token::TripleDoubleQuotedRawStringLiteral("test".to_string())
        ));
        assert!(!is_whitespace_token(&Token::NationalStringLiteral(
            "test".to_string()
        )));
        assert!(!is_whitespace_token(&Token::EscapedStringLiteral(
            "test".to_string()
        )));
        assert!(!is_whitespace_token(&Token::UnicodeStringLiteral(
            "test".to_string()
        )));
        assert!(!is_whitespace_token(&Token::HexStringLiteral(
            "test".to_string()
        )));
    }

    #[test]
    fn test_general() {
        // Test general safe tokens
        assert!(!is_whitespace_token(&Token::EOF));
        assert!(!is_whitespace_token(&Token::Word(Word {
            value: "SELECT".to_string(),
            quote_style: None,
            keyword: Keyword::SELECT,
        })));
        assert!(is_whitespace_token(&Token::Whitespace(
            Whitespace::SingleLineComment {
                comment: "test".to_string(),
                prefix: "".to_string()
            }
        )));
    }
}
