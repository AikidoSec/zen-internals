#[cfg(test)]
mod tests {
    use crate::sql_injection::is_dangerous_token::is_dangerous_token;
    use sqlparser::ast::DollarQuotedString;
    use sqlparser::keywords::Keyword;
    use sqlparser::tokenizer::{Token, Whitespace, Word};

    #[test]
    fn test_safe_tokens() {
        // Test various safe tokens
        assert!(!is_dangerous_token(&Token::SingleQuotedString(
            "test".to_string()
        )));
        assert!(!is_dangerous_token(&Token::DoubleQuotedString(
            "test".to_string()
        )));
        assert!(!is_dangerous_token(&Token::TripleSingleQuotedString(
            "test".to_string()
        )));
        assert!(!is_dangerous_token(&Token::TripleDoubleQuotedString(
            "test".to_string()
        )));
        assert!(!is_dangerous_token(&Token::DollarQuotedString(
            DollarQuotedString {
                value: "test".to_string(),
                tag: None,
            }
        )));
        assert!(!is_dangerous_token(&Token::SingleQuotedByteStringLiteral(
            "test".to_string()
        )));
        assert!(!is_dangerous_token(&Token::DoubleQuotedByteStringLiteral(
            "test".to_string()
        )));
        assert!(!is_dangerous_token(
            &Token::TripleSingleQuotedByteStringLiteral("test".to_string())
        ));
        assert!(!is_dangerous_token(
            &Token::TripleDoubleQuotedByteStringLiteral("test".to_string())
        ));
        assert!(!is_dangerous_token(&Token::SingleQuotedRawStringLiteral(
            "test".to_string()
        )));
        assert!(!is_dangerous_token(&Token::DoubleQuotedRawStringLiteral(
            "test".to_string()
        )));
        assert!(!is_dangerous_token(
            &Token::TripleSingleQuotedRawStringLiteral("test".to_string())
        ));
        assert!(!is_dangerous_token(
            &Token::TripleDoubleQuotedRawStringLiteral("test".to_string())
        ));
        assert!(!is_dangerous_token(&Token::NationalStringLiteral(
            "test".to_string()
        )));
        assert!(!is_dangerous_token(&Token::EscapedStringLiteral(
            "test".to_string()
        )));
        assert!(!is_dangerous_token(&Token::UnicodeStringLiteral(
            "test".to_string()
        )));
        assert!(!is_dangerous_token(&Token::HexStringLiteral(
            "test".to_string()
        )));
    }

    #[test]
    fn test_general_safe_tokens() {
        // Test general safe tokens
        assert!(!is_dangerous_token(&Token::EOF));
        assert!(!is_dangerous_token(&Token::Word(Word {
            value: "SELECT".to_string(),
            quote_style: None,
            keyword: Keyword::SELECT,
        })));
        assert!(!is_dangerous_token(&Token::Whitespace(
            Whitespace::SingleLineComment {
                comment: "test".to_string(),
                prefix: "".to_string()
            }
        )));
    }

    #[test]
    fn test_dangerous_tokens() {
        // Test various dangerous tokens
        assert!(is_dangerous_token(&Token::Number("123".to_string(), true))); // Unsigned numeric literal
        assert!(is_dangerous_token(&Token::Char('a'))); // Unrecognized character
        assert!(is_dangerous_token(&Token::Comma)); // Comma token
        assert!(is_dangerous_token(&Token::DoubleEq)); // Double equals sign
        assert!(is_dangerous_token(&Token::Eq)); // Equality operator
        assert!(is_dangerous_token(&Token::Neq)); // Not equals operator
        assert!(is_dangerous_token(&Token::Lt)); // Less than operator
        assert!(is_dangerous_token(&Token::Gt)); // Greater than operator
        assert!(is_dangerous_token(&Token::LtEq)); // Less than or equals operator
        assert!(is_dangerous_token(&Token::GtEq)); // Greater than or equals operator
        assert!(is_dangerous_token(&Token::Plus)); // Plus operator
        assert!(is_dangerous_token(&Token::Minus)); // Minus operator
        assert!(is_dangerous_token(&Token::Mul)); // Multiplication operator
        assert!(is_dangerous_token(&Token::Div)); // Division operator
        assert!(is_dangerous_token(&Token::Mod)); // Modulo operator
        assert!(is_dangerous_token(&Token::StringConcat)); // String concatenation operator
        assert!(is_dangerous_token(&Token::LParen)); // Left parenthesis
        assert!(is_dangerous_token(&Token::RParen)); // Right parenthesis
        assert!(is_dangerous_token(&Token::Period)); // Period token
        assert!(is_dangerous_token(&Token::SemiColon)); // Semicolon token
        assert!(is_dangerous_token(&Token::Backslash)); // Backslash token
        assert!(is_dangerous_token(&Token::Ampersand)); // Ampersand token
        assert!(is_dangerous_token(&Token::Pipe)); // Pipe token
        assert!(is_dangerous_token(&Token::Caret)); // Caret token
        assert!(is_dangerous_token(&Token::AtSign)); // At sign token
        assert!(is_dangerous_token(&Token::Placeholder(
            "placeholder".to_string()
        ))); // Placeholder token
        assert!(is_dangerous_token(&Token::Arrow)); // Arrow operator
        assert!(is_dangerous_token(&Token::LongArrow)); // Long arrow operator
        assert!(is_dangerous_token(&Token::HashArrow)); // Hash arrow operator
        assert!(is_dangerous_token(&Token::HashLongArrow)); // Hash long arrow operator
        assert!(is_dangerous_token(&Token::AtQuestion)); // JSON path question operator
        assert!(is_dangerous_token(&Token::Question)); // JSON key existence operator
        assert!(is_dangerous_token(&Token::CustomBinaryOperator(
            "custom_op".to_string()
        ))); // Custom binary operator
    }
}
