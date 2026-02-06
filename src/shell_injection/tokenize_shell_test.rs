#[cfg(test)]
mod tests {
    use crate::shell_injection::tokenize_shell::tokenize_shell;
    use crate::shell_injection::tokenize_shell::ShellToken;

    #[test]
    fn test_simple_command() {
        let tokens = tokenize_shell("ls");
        assert_eq!(tokens, vec![ShellToken::Text("ls".to_string())]);
    }

    #[test]
    fn test_command_with_args() {
        let tokens = tokenize_shell("ls -la /tmp");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("ls".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("-la".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("/tmp".to_string()),
            ]
        );
    }

    #[test]
    fn test_semicolon_separates_commands() {
        let tokens = tokenize_shell("ls; rm -rf /");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("ls".to_string()),
                ShellToken::Operator(";".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("rm".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("-rf".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("/".to_string()),
            ]
        );
    }

    #[test]
    fn test_pipe() {
        let tokens = tokenize_shell("cat file | grep pattern");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("cat".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("file".to_string()),
                ShellToken::Whitespace,
                ShellToken::Operator("|".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("grep".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("pattern".to_string()),
            ]
        );
    }

    #[test]
    fn test_and_operator() {
        let tokens = tokenize_shell("cmd1 && cmd2");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("cmd1".to_string()),
                ShellToken::Whitespace,
                ShellToken::Operator("&&".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("cmd2".to_string()),
            ]
        );
    }

    #[test]
    fn test_or_operator() {
        let tokens = tokenize_shell("cmd1 || cmd2");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("cmd1".to_string()),
                ShellToken::Whitespace,
                ShellToken::Operator("||".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("cmd2".to_string()),
            ]
        );
    }

    #[test]
    fn test_background() {
        let tokens = tokenize_shell("sleep 10 &");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("sleep".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("10".to_string()),
                ShellToken::Whitespace,
                ShellToken::Operator("&".to_string()),
            ]
        );
    }

    #[test]
    fn test_redirect_out() {
        let tokens = tokenize_shell("echo hello > file.txt");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("hello".to_string()),
                ShellToken::Whitespace,
                ShellToken::Operator(">".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("file.txt".to_string()),
            ]
        );
    }

    #[test]
    fn test_redirect_append() {
        let tokens = tokenize_shell("echo data >> file.txt");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("data".to_string()),
                ShellToken::Whitespace,
                ShellToken::Operator(">>".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("file.txt".to_string()),
            ]
        );
    }

    #[test]
    fn test_redirect_stderr() {
        let tokens = tokenize_shell("cmd 2>&1");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("cmd".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("2".to_string()),
                ShellToken::Operator(">&".to_string()),
                ShellToken::Text("1".to_string()),
            ]
        );
    }

    #[test]
    fn test_heredoc_operator() {
        let tokens = tokenize_shell("cat <<EOF");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("cat".to_string()),
                ShellToken::Whitespace,
                ShellToken::Operator("<<".to_string()),
                ShellToken::Text("EOF".to_string()),
            ]
        );
    }

    #[test]
    fn test_heredoc_dash_operator() {
        let tokens = tokenize_shell("cat <<-EOF");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("cat".to_string()),
                ShellToken::Whitespace,
                ShellToken::Operator("<<-".to_string()),
                ShellToken::Text("EOF".to_string()),
            ]
        );
    }

    #[test]
    fn test_clobber_operator() {
        let tokens = tokenize_shell("echo x >| file");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("x".to_string()),
                ShellToken::Whitespace,
                ShellToken::Operator(">|".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("file".to_string()),
            ]
        );
    }

    #[test]
    fn test_redirect_read_write() {
        let tokens = tokenize_shell("cmd <>file");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("cmd".to_string()),
                ShellToken::Whitespace,
                ShellToken::Operator("<>".to_string()),
                ShellToken::Text("file".to_string()),
            ]
        );
    }

    #[test]
    fn test_redirect_input_dup() {
        let tokens = tokenize_shell("cmd <&3");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("cmd".to_string()),
                ShellToken::Whitespace,
                ShellToken::Operator("<&".to_string()),
                ShellToken::Text("3".to_string()),
            ]
        );
    }

    #[test]
    fn test_double_semicolon() {
        let tokens = tokenize_shell("pattern) cmd;;");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("pattern".to_string()),
                ShellToken::Operator(")".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("cmd".to_string()),
                ShellToken::Operator(";;".to_string()),
            ]
        );
    }

    #[test]
    fn test_single_quoted_string() {
        let tokens = tokenize_shell("echo 'hello world'");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::SingleQuoted("hello world".to_string()),
            ]
        );
    }

    #[test]
    fn test_single_quotes_preserve_everything() {
        let tokens = tokenize_shell("echo '$USER ; | & $(cmd) `cmd`'");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::SingleQuoted("$USER ; | & $(cmd) `cmd`".to_string()),
            ]
        );
    }

    #[test]
    fn test_double_quoted_simple() {
        let tokens = tokenize_shell("echo \"hello world\"");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("hello world".to_string()),
            ]
        );
    }

    #[test]
    fn test_double_quoted_with_dollar() {
        let tokens = tokenize_shell("echo \"$USER\"");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Dollar,
                ShellToken::Text("USER".to_string()),
            ]
        );
    }

    #[test]
    fn test_double_quoted_with_backtick() {
        let tokens = tokenize_shell("echo \"`whoami`\"");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Backtick,
                ShellToken::Text("whoami".to_string()),
                ShellToken::Backtick,
            ]
        );
    }

    #[test]
    fn test_double_quoted_escaped_dollar() {
        let tokens = tokenize_shell("echo \"\\$USER\"");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                // \$ escapes the $, so it becomes literal text, no Dollar token
                ShellToken::Text("$USER".to_string()),
            ]
        );
    }

    #[test]
    fn test_double_quoted_escaped_backtick() {
        let tokens = tokenize_shell("echo \"\\`cmd\\`\"");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("`cmd`".to_string()),
            ]
        );
    }

    #[test]
    fn test_double_quoted_literal_backslash_other_char() {
        // \a inside double quotes: backslash is literal (per POSIX)
        let tokens = tokenize_shell("echo \"\\a\"");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("\\a".to_string()),
            ]
        );
    }

    #[test]
    fn test_dollar_variable() {
        let tokens = tokenize_shell("echo $USER");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Dollar,
                ShellToken::Text("USER".to_string()),
            ]
        );
    }

    #[test]
    fn test_dollar_brace() {
        let tokens = tokenize_shell("echo ${USER}");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Dollar,
                ShellToken::Text("{USER}".to_string()),
            ]
        );
    }

    #[test]
    fn test_dollar_paren_command_substitution() {
        let tokens = tokenize_shell("echo $(whoami)");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Dollar,
                ShellToken::Operator("(".to_string()),
                ShellToken::Text("whoami".to_string()),
                ShellToken::Operator(")".to_string()),
            ]
        );
    }

    #[test]
    fn test_backtick_command_substitution() {
        let tokens = tokenize_shell("echo `whoami`");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Backtick,
                ShellToken::Text("whoami".to_string()),
                ShellToken::Backtick,
            ]
        );
    }

    #[test]
    fn test_comment() {
        let tokens = tokenize_shell("echo hello # this is a comment");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("hello".to_string()),
                ShellToken::Whitespace,
                ShellToken::Comment("# this is a comment".to_string()),
            ]
        );
    }

    #[test]
    fn test_hash_in_word_is_not_comment() {
        let tokens = tokenize_shell("echo foo#bar");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("foo#bar".to_string()),
            ]
        );
    }

    #[test]
    fn test_hash_after_operator_is_comment() {
        let tokens = tokenize_shell("cmd;# comment");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("cmd".to_string()),
                ShellToken::Operator(";".to_string()),
                ShellToken::Comment("# comment".to_string()),
            ]
        );
    }

    #[test]
    fn test_backslash_escape_normal_mode() {
        let tokens = tokenize_shell("echo hello\\ world");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                // \<space> makes the space literal, part of the word
                ShellToken::Text("hello\\ world".to_string()),
            ]
        );
    }

    #[test]
    fn test_backslash_escape_semicolon() {
        let tokens = tokenize_shell("echo hello\\;world");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("hello\\;world".to_string()),
            ]
        );
    }

    #[test]
    fn test_line_continuation() {
        let tokens = tokenize_shell("echo hel\\\nlo");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                // \<newline> is line continuation: both chars removed, lines joined
                ShellToken::Text("hello".to_string()),
            ]
        );
    }

    #[test]
    fn test_newline_is_token() {
        let tokens = tokenize_shell("echo hello\necho world");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("hello".to_string()),
                ShellToken::Newline,
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("world".to_string()),
            ]
        );
    }

    #[test]
    fn test_glob_chars_are_text() {
        let tokens = tokenize_shell("echo *.txt");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("*.txt".to_string()),
            ]
        );
    }

    #[test]
    fn test_tilde_at_word_start() {
        let tokens = tokenize_shell("ls ~/.ssh");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("ls".to_string()),
                ShellToken::Whitespace,
                ShellToken::Tilde,
                ShellToken::Text("/.ssh".to_string()),
            ]
        );
    }

    #[test]
    fn test_tilde_mid_word_is_text() {
        let tokens = tokenize_shell("ls foo~bar");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("ls".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("foo~bar".to_string()),
            ]
        );
    }

    #[test]
    fn test_equals_is_text() {
        let tokens = tokenize_shell("VAR=value cmd");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("VAR=value".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("cmd".to_string()),
            ]
        );
    }

    #[test]
    fn test_braces_are_text() {
        let tokens = tokenize_shell("echo ${HOME}");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Dollar,
                ShellToken::Text("{HOME}".to_string()),
            ]
        );
    }

    #[test]
    fn test_brackets_are_text() {
        let tokens = tokenize_shell("echo [abc]");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("[abc]".to_string()),
            ]
        );
    }

    #[test]
    fn test_unclosed_single_quote_returns_empty() {
        let tokens = tokenize_shell("echo 'unclosed");
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_unclosed_double_quote_returns_empty() {
        let tokens = tokenize_shell("echo \"unclosed");
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_empty_input() {
        let tokens = tokenize_shell("");
        assert!(tokens.is_empty());
    }

    #[test]
    fn test_whitespace_only() {
        let tokens = tokenize_shell("   ");
        assert_eq!(tokens, vec![ShellToken::Whitespace]);
    }

    #[test]
    fn test_collapsed_whitespace() {
        let tokens = tokenize_shell("echo   hello");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("hello".to_string()),
            ]
        );
    }

    #[test]
    fn test_subshell() {
        let tokens = tokenize_shell("(echo hello)");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Operator("(".to_string()),
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("hello".to_string()),
                ShellToken::Operator(")".to_string()),
            ]
        );
    }

    #[test]
    fn test_real_world_curl() {
        let tokens = tokenize_shell("curl -s 'https://api.example.com/data'");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("curl".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("-s".to_string()),
                ShellToken::Whitespace,
                ShellToken::SingleQuoted("https://api.example.com/data".to_string()),
            ]
        );
    }

    #[test]
    fn test_real_world_ffmpeg() {
        let tokens = tokenize_shell("ffmpeg -i \"input.mp4\" -ss 00:00:01 -frames:v 1 out.jpg");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("ffmpeg".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("-i".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("input.mp4".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("-ss".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("00:00:01".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("-frames:v".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("1".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("out.jpg".to_string()),
            ]
        );
    }

    #[test]
    fn test_real_world_redirect_stderr() {
        let tokens = tokenize_shell("cmd 2>/dev/null");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("cmd".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("2".to_string()),
                ShellToken::Operator(">".to_string()),
                ShellToken::Text("/dev/null".to_string()),
            ]
        );
    }

    #[test]
    fn test_double_quote_line_continuation() {
        let tokens = tokenize_shell("echo \"hello\\\nworld\"");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                // \<newline> inside double quotes is line continuation
                ShellToken::Text("helloworld".to_string()),
            ]
        );
    }

    #[test]
    fn test_adjacent_quotes() {
        let tokens = tokenize_shell("echo 'a'\"b\"c");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::SingleQuoted("a".to_string()),
                ShellToken::Text("b".to_string()),
                ShellToken::Text("c".to_string()),
            ]
        );
    }

    #[test]
    fn test_comment_at_start() {
        let tokens = tokenize_shell("# this is a comment\necho hello");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Comment("# this is a comment".to_string()),
                ShellToken::Newline,
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Text("hello".to_string()),
            ]
        );
    }

    #[test]
    fn test_dollar_at_end() {
        let tokens = tokenize_shell("echo $");
        assert_eq!(
            tokens,
            vec![
                ShellToken::Text("echo".to_string()),
                ShellToken::Whitespace,
                ShellToken::Dollar,
            ]
        );
    }
}
