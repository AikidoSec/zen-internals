#[derive(Debug, Clone, PartialEq)]
pub enum ShellToken {
    /// Regular word characters (letters, digits, -, /, ., _, *, ?, !, =, [, ], {, }, ^, @, etc.)
    Text(String),
    /// Spaces and tabs (consecutive whitespace collapsed into one token)
    Whitespace,
    /// Newline character
    Newline,
    /// Content between single quotes (everything literal)
    SingleQuoted(String),
    /// Control or redirection operator: |, ||, &&, ;, ;;, &, (, ), <, >, >>, <<, <&, >&, <>, >|, <<-
    Operator(String),
    /// Dollar sign — expansion trigger ($VAR, ${VAR}, $(cmd), $((expr)))
    Dollar,
    /// Backtick — command substitution delimiter
    Backtick,
    /// Tilde at word start — triggers tilde expansion (~, ~/path, ~user)
    Tilde,
    /// Comment (# to end of line)
    Comment(String),
}

/// Tokenizes a POSIX shell command string into a list of tokens.
///
/// Returns an empty Vec on tokenization error (e.g. unclosed quotes).
/// This matches the pattern used by the SQL tokenizer.
pub fn tokenize_shell(input: &str) -> Vec<ShellToken> {
    let chars: Vec<char> = input.chars().collect();
    let len = chars.len();
    let mut tokens = Vec::new();
    let mut i = 0;
    let mut text_buf = String::new();

    while i < len {
        let c = chars[i];

        match c {
            // Single-quoted string: everything literal until closing '
            '\'' => {
                flush_text(&mut text_buf, &mut tokens);
                i += 1;
                let start = i;
                while i < len && chars[i] != '\'' {
                    i += 1;
                }
                if i >= len {
                    // Unclosed single quote — tokenization error
                    return Vec::new();
                }
                let content: String = chars[start..i].iter().collect();
                tokens.push(ShellToken::SingleQuoted(content));
                i += 1; // skip closing '
            }

            // Double-quoted string: no token emitted for " itself
            // $, ` remain special inside; \ escapes $, `, ", \, \n
            '"' => {
                flush_text(&mut text_buf, &mut tokens);
                i += 1; // skip opening "
                let mut dq_text = String::new();

                loop {
                    if i >= len {
                        // Unclosed double quote — tokenization error
                        return Vec::new();
                    }
                    let dc = chars[i];
                    match dc {
                        '"' => {
                            // Closing double quote
                            flush_dq_text(&mut dq_text, &mut tokens);
                            i += 1;
                            break;
                        }
                        '$' => {
                            flush_dq_text(&mut dq_text, &mut tokens);
                            tokens.push(ShellToken::Dollar);
                            i += 1;
                        }
                        '`' => {
                            flush_dq_text(&mut dq_text, &mut tokens);
                            tokens.push(ShellToken::Backtick);
                            i += 1;
                        }
                        '\\' => {
                            if i + 1 < len {
                                let next = chars[i + 1];
                                if next == '$' || next == '`' || next == '"' || next == '\\' {
                                    // Escape: next char is literal text (not structural)
                                    dq_text.push(next);
                                    i += 2;
                                } else if next == '\n' {
                                    // Line continuation inside double quotes
                                    i += 2;
                                } else {
                                    // Literal backslash + next char (both preserved per POSIX)
                                    dq_text.push('\\');
                                    dq_text.push(next);
                                    i += 2;
                                }
                            } else {
                                // Backslash at end of input inside double quotes
                                dq_text.push('\\');
                                i += 1;
                            }
                        }
                        _ => {
                            dq_text.push(dc);
                            i += 1;
                        }
                    }
                }
            }

            // Backslash (escape) in normal mode
            '\\' => {
                if i + 1 < len {
                    let next = chars[i + 1];
                    if next == '\n' {
                        // Line continuation: skip both characters (per POSIX)
                        i += 2;
                    } else {
                        // Escape: both chars become text (next char is literal)
                        text_buf.push('\\');
                        text_buf.push(next);
                        i += 2;
                    }
                } else {
                    // Trailing backslash
                    text_buf.push('\\');
                    i += 1;
                }
            }

            // Comment: # at word boundary (text buffer empty)
            '#' if text_buf.is_empty() => {
                let start = i;
                while i < len && chars[i] != '\n' {
                    i += 1;
                }
                let comment: String = chars[start..i].iter().collect();
                tokens.push(ShellToken::Comment(comment));
            }

            // # in the middle of a word is not a comment
            '#' => {
                text_buf.push('#');
                i += 1;
            }

            // Dollar sign: expansion trigger
            '$' => {
                flush_text(&mut text_buf, &mut tokens);
                tokens.push(ShellToken::Dollar);
                i += 1;
            }

            // Backtick: command substitution delimiter
            '`' => {
                flush_text(&mut text_buf, &mut tokens);
                tokens.push(ShellToken::Backtick);
                i += 1;
            }

            // Operator characters with multi-char lookahead
            '|' => {
                flush_text(&mut text_buf, &mut tokens);
                if i + 1 < len && chars[i + 1] == '|' {
                    tokens.push(ShellToken::Operator("||".to_string()));
                    i += 2;
                } else {
                    tokens.push(ShellToken::Operator("|".to_string()));
                    i += 1;
                }
            }

            '&' => {
                flush_text(&mut text_buf, &mut tokens);
                if i + 1 < len && chars[i + 1] == '&' {
                    tokens.push(ShellToken::Operator("&&".to_string()));
                    i += 2;
                } else {
                    tokens.push(ShellToken::Operator("&".to_string()));
                    i += 1;
                }
            }

            ';' => {
                flush_text(&mut text_buf, &mut tokens);
                if i + 1 < len && chars[i + 1] == ';' {
                    tokens.push(ShellToken::Operator(";;".to_string()));
                    i += 2;
                } else {
                    tokens.push(ShellToken::Operator(";".to_string()));
                    i += 1;
                }
            }

            '>' => {
                flush_text(&mut text_buf, &mut tokens);
                if i + 1 < len {
                    match chars[i + 1] {
                        '>' => {
                            tokens.push(ShellToken::Operator(">>".to_string()));
                            i += 2;
                        }
                        '&' => {
                            tokens.push(ShellToken::Operator(">&".to_string()));
                            i += 2;
                        }
                        '|' => {
                            tokens.push(ShellToken::Operator(">|".to_string()));
                            i += 2;
                        }
                        _ => {
                            tokens.push(ShellToken::Operator(">".to_string()));
                            i += 1;
                        }
                    }
                } else {
                    tokens.push(ShellToken::Operator(">".to_string()));
                    i += 1;
                }
            }

            '<' => {
                flush_text(&mut text_buf, &mut tokens);
                if i + 1 < len {
                    match chars[i + 1] {
                        '<' => {
                            if i + 2 < len && chars[i + 2] == '-' {
                                tokens.push(ShellToken::Operator("<<-".to_string()));
                                i += 3;
                            } else {
                                tokens.push(ShellToken::Operator("<<".to_string()));
                                i += 2;
                            }
                        }
                        '&' => {
                            tokens.push(ShellToken::Operator("<&".to_string()));
                            i += 2;
                        }
                        '>' => {
                            tokens.push(ShellToken::Operator("<>".to_string()));
                            i += 2;
                        }
                        _ => {
                            tokens.push(ShellToken::Operator("<".to_string()));
                            i += 1;
                        }
                    }
                } else {
                    tokens.push(ShellToken::Operator("<".to_string()));
                    i += 1;
                }
            }

            '(' => {
                flush_text(&mut text_buf, &mut tokens);
                tokens.push(ShellToken::Operator("(".to_string()));
                i += 1;
            }

            ')' => {
                flush_text(&mut text_buf, &mut tokens);
                tokens.push(ShellToken::Operator(")".to_string()));
                i += 1;
            }

            // Whitespace (collapse consecutive spaces/tabs)
            ' ' | '\t' => {
                flush_text(&mut text_buf, &mut tokens);
                while i < len && (chars[i] == ' ' || chars[i] == '\t') {
                    i += 1;
                }
                tokens.push(ShellToken::Whitespace);
            }

            // Newline
            '\n' => {
                flush_text(&mut text_buf, &mut tokens);
                tokens.push(ShellToken::Newline);
                i += 1;
            }

            // Tilde at word start: expansion trigger (~, ~/path, ~user)
            '~' if text_buf.is_empty() => {
                tokens.push(ShellToken::Tilde);
                i += 1;
            }

            // Everything else is a word character
            _ => {
                text_buf.push(c);
                i += 1;
            }
        }
    }

    flush_text(&mut text_buf, &mut tokens);
    tokens
}

fn flush_text(buf: &mut String, tokens: &mut Vec<ShellToken>) {
    if !buf.is_empty() {
        tokens.push(ShellToken::Text(buf.clone()));
        buf.clear();
    }
}

fn flush_dq_text(buf: &mut String, tokens: &mut Vec<ShellToken>) {
    if !buf.is_empty() {
        tokens.push(ShellToken::Text(buf.clone()));
        buf.clear();
    }
}
