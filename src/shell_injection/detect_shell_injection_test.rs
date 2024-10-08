#[cfg(test)]
mod tests {
    use crate::shell_injection::detect_shell_injection::detect_shell_injection_stringified;
    use std::assert;

    fn is_shell_injection(command: &str, user_input: &str) {
        assert!(
            detect_shell_injection_stringified(command, user_input),
            "command: {}, userInput: {}",
            command,
            user_input
        );
    }

    fn is_not_shell_injection(command: &str, user_input: &str) {
        assert!(
            !detect_shell_injection_stringified(command, user_input),
            "command: {}, userInput: {}",
            command,
            user_input
        );
    }

    #[test]
    fn test_single_characters_ignored() {
        is_not_shell_injection("ls `", "`");
        is_not_shell_injection("ls *", "*");
        is_not_shell_injection("ls a", "a");
    }

    #[test]
    fn test_no_user_input() {
        is_not_shell_injection("ls", "");
        is_not_shell_injection("ls", " ");
        is_not_shell_injection("ls", "  ");
        is_not_shell_injection("ls", "   ");
    }

    #[test]
    fn test_user_input_not_in_command() {
        is_not_shell_injection("ls", "$(echo)");
    }

    #[test]
    fn test_user_input_longer_than_command() {
        is_not_shell_injection("`ls`", "`ls` `ls`");
    }

    #[test]
    fn test_detects_command_substitution() {
        is_shell_injection("ls $(echo)", "$(echo)");
        is_shell_injection("ls \"$(echo)\"", "$(echo)");
        is_shell_injection(
            "echo $(echo \"Inner: $(echo \"This is nested\")\")",
            "$(echo \"Inner: $(echo \"This is nested\")\")",
        );

        is_not_shell_injection("ls '$(echo)'", "$(echo)");
        is_not_shell_injection(
            "ls '$(echo \"Inner: $(echo \"This is nested\")\")'",
            "$(echo \"Inner: $(echo \"This is nested\")\")",
        );
    }

    #[test]
    fn test_detects_backticks() {
        is_shell_injection("echo `echo`", "`echo`");
    }

    #[test]
    fn test_checks_unsafely_quoted() {
        is_shell_injection("ls '$(echo)", "$(echo)");
    }

    #[test]
    fn test_single_quote_between_single_quotes() {
        is_shell_injection("ls ''single quote''", "'single quote'");
    }

    #[test]
    fn test_no_special_chars_inside_double_quotes() {
        is_shell_injection("ls \"whatever$\"", "whatever$");
        is_shell_injection("ls \"whatever!\"", "whatever!");
        is_shell_injection("ls \"whatever`\"", "whatever`");
    }

    #[test]
    fn test_no_semi_colon() {
        is_shell_injection("ls whatever;", "whatever;");
        is_not_shell_injection("ls \"whatever;\"", "whatever;");
        is_not_shell_injection("ls 'whatever;'", "whatever;");
    }

    #[test]
    fn test_rm_rf_executed_by_using_semi_colon() {
        is_shell_injection("ls; rm -rf", "; rm -rf");
    }

    #[test]
    fn test_rm_rf_is_flagged_as_shell_injection() {
        is_shell_injection("rm -rf", "rm -rf");
    }

    #[test]
    fn test_shell_injection_with_chained_commands_using_and() {
        is_shell_injection("ls && rm -rf /", "&& rm -rf /");
    }

    #[test]
    fn test_shell_injection_with_or_logic() {
        is_shell_injection("ls || echo 'malicious code'", "|| echo 'malicious code'");
    }

    #[test]
    fn test_detects_redirection_attempts() {
        is_shell_injection("ls > /dev/null", "> /dev/null");
        is_shell_injection("cat file.txt > /etc/passwd", "> /etc/passwd");
    }

    #[test]
    fn test_detects_append_redirection_attempts() {
        is_shell_injection("echo 'data' >> /etc/passwd", ">> /etc/passwd");
    }

    #[test]
    fn test_detects_pipe_character_as_shell_injection() {
        is_shell_injection("cat file.txt | grep 'password'", "| grep 'password'");
    }

    #[test]
    fn test_allows_safe_use_of_pipe_character_within_quotes() {
        is_not_shell_injection("echo '|'", "|");
    }

    #[test]
    fn test_detects_nested_command_substitution() {
        is_shell_injection("echo $(cat $(ls))", "$(cat $(ls))");
    }

    #[test]
    fn test_allows_safe_commands_within_single_quotes() {
        is_not_shell_injection("echo 'safe command'", "safe command");
    }

    #[test]
    fn test_detects_unsafe_use_of_variables() {
        is_shell_injection("echo $USER", "$USER");
        is_shell_injection("echo ${USER}", "${USER}");
        is_shell_injection("echo \"${USER}\"", "${USER}");
    }

    #[test]
    fn test_allows_safe_use_of_variables_within_quotes() {
        is_not_shell_injection("echo '$USER'", "$USER");
    }

    #[test]
    fn test_detects_subshell_execution_with_backticks_inside_double_quotes() {
        is_shell_injection("ls \"$(echo `whoami`)", "`whoami`");
    }

    #[test]
    fn test_detects_code_injection_with_newline_characters() {
        is_shell_injection("echo 'safe'\necho 'malicious'", "\necho 'malicious'");
    }

    #[test]
    fn test_detects_attempts_to_escape_out_of_quotes() {
        is_shell_injection(
            "echo \"safe\"; echo \"malicious\"",
            "\"; echo \"malicious\"",
        );
    }

    #[test]
    fn test_correctly_handles_whitespace_in_inputs() {
        is_not_shell_injection("ls", "   ");
        is_shell_injection("ls ; rm -rf /", "; rm -rf /");
    }

    #[test]
    fn test_detects_file_manipulation_commands() {
        is_shell_injection("touch /tmp/malicious", "touch /tmp/malicious");
        is_shell_injection("mv /tmp/safe /tmp/malicious", "mv /tmp/safe /tmp/malicious");
    }

    #[test]
    fn test_allows_commands_with_constants_that_resemble_user_input() {
        is_not_shell_injection("echo 'userInput'", "userInput");
    }

    #[test]
    fn test_recognizes_safe_paths_that_include_patterns_similar_to_user_input() {
        is_not_shell_injection(
            "ls /constant/path/without/user/input/",
            "/constant/path/without/user/input/",
        );
    }

    #[test]
    fn test_acknowledges_safe_use_of_special_characters_when_properly_encapsulated() {
        is_not_shell_injection("echo ';'", ";");
        is_not_shell_injection("echo '&&'", "&&");
        is_not_shell_injection("echo '||'", "||");
    }

    #[test]
    fn test_treats_encapsulated_redirection_and_pipe_symbols_as_safe() {
        is_not_shell_injection("echo 'data > file.txt'", "data > file.txt");
        is_not_shell_injection("echo 'find | grep'", "find | grep");
    }

    #[test]
    fn test_recognizes_safe_inclusion_of_special_patterns_within_quotes_as_non_injections() {
        is_not_shell_injection("echo '$(command)'", "$(command)");
    }

    #[test]
    fn test_considers_constants_with_semicolons_as_safe_when_non_executable() {
        is_not_shell_injection("echo 'text; more text'", "text; more text");
    }

    #[test]
    fn test_acknowledges_commands_that_look_dangerous_but_are_safe_due_to_quoting() {
        is_not_shell_injection("echo '; rm -rf /'", "; rm -rf /");
        is_not_shell_injection("echo '&& echo malicious'", "&& echo malicious");
    }

    #[test]
    fn test_recognizes_commands_with_newline_characters_as_safe_when_encapsulated() {
        is_not_shell_injection("echo 'line1\nline2'", "line1\nline2");
    }

    #[test]
    fn test_accepts_special_characters_in_constants_as_safe_when_no_execution() {
        is_not_shell_injection("echo '*'", "*");
        is_not_shell_injection("echo '?'", "?");
        is_not_shell_injection("echo '\\' ", "\\");
    }

    #[test]
    fn test_does_not_flag_command_with_matching_whitespace_as_injection() {
        is_not_shell_injection("ls -l", " "); // A single space is just an argument separator, not user input
    }

    #[test]
    fn test_ignores_commands_where_multiple_spaces_match_user_input() {
        is_not_shell_injection("ls   -l", "   "); // Multiple spaces between arguments should not be considered injection
    }

    #[test]
    fn test_does_not_consider_leading_whitespace_in_commands_as_user_input() {
        is_not_shell_injection("  ls -l", "  "); // Leading spaces before the command are not user-controlled
    }

    #[test]
    fn test_treats_trailing_whitespace_in_commands_as_non_injection() {
        is_not_shell_injection("ls -l ", " "); // Trailing space after the command is benign
    }

    #[test]
    fn test_recognizes_spaces_between_quotes_as_non_injective() {
        is_not_shell_injection("echo ' ' ", " "); // Space within quotes is part of the argument, not a separator
    }

    #[test]
    fn test_handles_spaces_within_quoted_arguments_correctly() {
        is_not_shell_injection("command 'arg with spaces'", " "); // Spaces within a quoted argument should not be flagged
    }

    #[test]
    fn test_correctly_interprets_spaces_in_mixed_argument_types() {
        is_not_shell_injection("command arg1 'arg with spaces' arg2", " "); // Mixed argument types with internal spaces are safe
    }

    #[test]
    fn test_ignores_spaces_in_commands_with_concatenated_arguments() {
        is_not_shell_injection("command 'arg1'arg2'arg3'", " "); // Lack of spaces in concatenated arguments is intentional and safe
    }

    #[test]
    fn test_does_not_flag_spaces_in_commands_with_no_arguments() {
        is_not_shell_injection("command", " "); // No arguments mean spaces are irrelevant
    }

    #[test]
    fn test_considers_spaces_in_environment_variable_assignments_as_safe() {
        is_not_shell_injection("ENV_VAR='value' command", " "); // Spaces around environment variable assignments are not injections
    }

    #[test]
    fn test_new_lines_in_commands_are_considered_injections() {
        is_shell_injection("ls \nrm", "\nrm");
        is_shell_injection("ls \nrm -rf", "\nrm -rf");
    }

    #[test]
    fn test_new_lines_alone_are_not_considered_injections() {
        is_not_shell_injection("ls\n\n", "\n\n");
    }

    #[test]
    fn test_certain_commands_are_always_flagged_as_dangerous() {
        is_shell_injection("/bin/rm -rf", "/bin/rm -rf");
        is_shell_injection("rm -rf", "rm -rf");
        is_shell_injection("rm -rf /", "rm -rf /");
        is_shell_injection("sleep 10", "sleep 10");
        is_shell_injection("sleep 10 &", "sleep 10 &");
        is_shell_injection("shutdown -h now", "shutdown -h now");
        is_shell_injection("halt", "halt");
        is_shell_injection("poweroff", "poweroff");
        is_shell_injection("reboot", "reboot");
        is_shell_injection("reboot -f", "reboot -f");
        is_shell_injection("ifconfig", "ifconfig");
        is_shell_injection("ifconfig -a", "ifconfig -a");
        is_shell_injection("kill", "kill");
        is_shell_injection("killall", "killall");
        is_shell_injection("killall -9", "killall -9");
        is_shell_injection("chmod", "chmod");
        is_shell_injection("chmod 777", "chmod 777");
        is_shell_injection("chown", "chown");
        is_shell_injection("chown root", "chown root");
    }

    #[test]
    fn test_rm_being_part_of_other_commands() {
        is_shell_injection(
            "find /path/to/search -type f -name \"pattern\" | xargs rm",
            "rm",
        );
        is_shell_injection(
            "find /path/to/search -type f -name \"pattern\" -exec rm {} \\;",
            "rm",
        );
        is_shell_injection("ls .|rm", "rm");
    }

    #[test]
    fn test_ignores_dangerous_commands_if_part_of_string() {
        is_not_shell_injection("binary sleepwithme", "sleepwithme");
        is_not_shell_injection("binary rm-rf", "rm-rf");
        is_not_shell_injection("term", "term");
        is_not_shell_injection("rm /files/rm.txt", "rm.txt");
    }

    #[test]
    fn test_does_not_flag_domain_name_as_argument_unless_contains_backticks() {
        is_not_shell_injection("binary --domain www.example.com", "www.example.com");
        is_not_shell_injection(
            "binary --domain https://www.example.com",
            "https://www.example.com",
        );

        is_shell_injection(
            "binary --domain www.example`whoami`.com",
            "www.example`whoami`.com",
        );
        is_shell_injection(
            "binary --domain https://www.example`whoami`.com",
            "https://www.example`whoami`.com",
        );
    }

    #[test]
    fn test_flags_colon_if_used_as_command() {
        is_shell_injection(":|echo", ":|");
        is_shell_injection(":| echo", ":|");
        is_shell_injection(": | echo", ": |");
    }

    #[test]
    fn test_detects_shell_injection() {
        is_shell_injection("/usr/bin/kill", "/usr/bin/kill");
    }

    #[test]
    fn test_detects_shell_injection_with_uppercase_path() {
        is_shell_injection("/usr/bIn/kill", "/usr/bIn/kill");
    }

    #[test]
    fn test_detects_shell_injection_with_uppercase_command() {
        is_shell_injection("/bin/CAT", "/bin/CAT");
    }

    #[test]
    fn test_detects_shell_injection_with_uppercase_path_and_command() {
        is_shell_injection("/bIn/LS -la", "/bIn/LS -la");
    }

    #[test]
    fn test_shell_injection_with_multiple_slashes() {
        is_shell_injection("//bin/ls", "//bin/ls");
        is_shell_injection("///bin/ls", "///bin/ls");
    }

    #[test]
    fn test_shell_injection_with_dotdot() {
        is_shell_injection("../bin/ls", "../bin/ls");
        is_shell_injection("../../bin/ls", "../../bin/ls");
        is_shell_injection("/../bin/ls", "/../bin/ls");
        is_shell_injection("/./bin/ls", "/./bin/ls");
    }

    #[test]
    fn test_shell_injection_with_tilde() {
        is_shell_injection("echo ~", "~");
        is_shell_injection("ls ~/.ssh", "~/.ssh");
    }

    #[test]
    fn test_no_shell_injection_with_tilde() {
        is_not_shell_injection("~", "~");
        is_not_shell_injection("ls ~/path", "path");
    }

    #[test]
    fn test_real_case() {
        is_shell_injection(
            "command -disable-update-check -target https://examplx.com|curl+https://cde-123.abc.domain.com+%23 -json-export /tmp/5891/8526757.json -tags microsoft,windows,exchange,iis,gitlab,oracle,cisco,joomla -stats -stats-interval 3 -retries 3 -no-stdin",
            "https://examplx.com|curl+https://cde-123.abc.domain.com+%23",
        );
    }

    #[test]
    fn test_false_positive_with_email() {
        is_not_shell_injection(
            "echo token | docker login --username john.doe@acme.com --password-stdin hub.acme.com",
            "john.doe@acme.com",
        );
    }

    #[test]
    fn test_at_sign_with_shell_syntax() {
        is_shell_injection("'echo \"${array[@]}\"'", "${array[@]}");
        is_shell_injection("echo $@", "$@");
    }

    #[test]
    fn test_allows_comma_separated_list() {
        is_not_shell_injection(
            "command -tags php,laravel,drupal,phpmyadmin,symfony -stats",
            "php,laravel,drupal,phpmyadmin,symfony",
        );
    }

    #[test]
    fn test_it_flags_comma_in_loop() {
        is_shell_injection(
            "command for (( i=0, j=10; i<j; i++, j-- )) do echo \"$i $j\" done",
            "for (( i=0, j=10; i<j; i++, j-- ))",
        );
    }
}
