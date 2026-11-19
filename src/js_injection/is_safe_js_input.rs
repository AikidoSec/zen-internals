use oxc_lexer::TokenKind;

use super::have_tokens_changed::has_line_break;
use super::tokenize_code::tokenize_code;

pub fn is_safe_js_input(user_input: &str, sourcetype: i32) -> bool {
    if matches!(
        user_input.trim_matches(is_js_whitespace),
        "true" | "false" | "null"
    ) {
        return true;
    }
    if !user_input.bytes().any(|byte| byte.is_ascii_digit()) {
        return false;
    }
    // Raw lexer diagnostics omit deferred Unicode validation.
    if !user_input.is_ascii()
        && user_input
            .chars()
            .any(|ch| !ch.is_ascii() && !is_js_whitespace(ch))
    {
        return false;
    }
    let Some(tokens) = tokenize_code(user_input, sourcetype) else {
        return false;
    };
    if tokens.has_errors()
        || tokens.comments().next().is_some()
        || user_input.trim_start_matches('\u{feff}').starts_with("#!")
    {
        return false;
    }

    let mut groups = Vec::new();
    let mut expecting_operand = true;
    let mut pending_unary = false;
    let mut left_is_unary = false;
    let mut ended_statement = false;
    let mut previous_end = 0;
    for (kind, span) in tokens.tokens() {
        match kind {
            TokenKind::Number => {
                if !expecting_operand
                    && (!groups.is_empty()
                        || !has_line_break(&user_input[previous_end..span.start]))
                {
                    return false;
                }
                expecting_operand = false;
                left_is_unary = pending_unary;
                pending_unary = false;
                ended_statement = false;
            }
            TokenKind::Plus | TokenKind::Minus if expecting_operand => {
                pending_unary = true;
                ended_statement = false;
            }
            TokenKind::LParen if expecting_operand => {
                groups.push(pending_unary);
                pending_unary = false;
                ended_statement = false;
            }
            TokenKind::RParen if !expecting_operand => {
                let Some(unary) = groups.pop() else {
                    return false;
                };
                left_is_unary = unary;
            }
            TokenKind::Plus
            | TokenKind::Minus
            | TokenKind::Star
            | TokenKind::Slash
            | TokenKind::Percent
            | TokenKind::StarStar
            | TokenKind::Comma
                if !expecting_operand =>
            {
                if kind == TokenKind::StarStar && left_is_unary {
                    return false;
                }
                expecting_operand = true;
                pending_unary = false;
                ended_statement = false;
            }
            TokenKind::Semi if !expecting_operand && groups.is_empty() => {
                expecting_operand = true;
                pending_unary = false;
                ended_statement = true;
            }
            _ => return false,
        }
        previous_end = span.end;
    }
    groups.is_empty() && (!expecting_operand || ended_statement)
}

fn is_js_whitespace(ch: char) -> bool {
    ch == '\u{feff}' || (ch.is_whitespace() && ch != '\u{85}')
}
