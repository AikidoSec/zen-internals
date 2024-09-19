#[cfg(test)]
mod tests {
    use crate::shell_injection::contains_shell_syntax::contains_shell_syntax;
    #[test]
    fn test_detects_shell_syntax() {
        assert_eq!(contains_shell_syntax("", ""), false);
        assert_eq!(contains_shell_syntax("hello", "hello"), false);
        assert_eq!(contains_shell_syntax("\n", "\n"), false);
        assert_eq!(contains_shell_syntax("\n\n", "\n\n"), false);

        assert_eq!(contains_shell_syntax("$(command)", "$(command)"), true);
        assert_eq!(
            contains_shell_syntax("$(command arg arg)", "$(command arg arg"),
            true
        );
        assert_eq!(contains_shell_syntax("`command`", "`command`"), true);
        assert_eq!(contains_shell_syntax("\narg", "\narg"), true);
        assert_eq!(contains_shell_syntax("\targ", "\targ"), true);

        assert_eq!(contains_shell_syntax("\narg\n", "\narg\n"), true);
        assert_eq!(contains_shell_syntax("arg\n", "arg\n"), true);
        assert_eq!(contains_shell_syntax("arg\narg", "arg\narg"), true);
        assert_eq!(contains_shell_syntax("rm -rf", "rm -rf"), true);
        assert_eq!(contains_shell_syntax("/bin/rm -rf", "/bin/rm -rf"), true);
        assert_eq!(contains_shell_syntax("/bin/rm", "/bin/rm"), true);
        assert_eq!(contains_shell_syntax("/sbin/sleep", "/sbin/sleep"), true);
        assert_eq!(
            contains_shell_syntax("/usr/bin/kill", "/usr/bin/kill"),
            true
        );

        assert_eq!(
            contains_shell_syntax("/usr/bin/killall", "/usr/bin/killall"),
            true
        );
        assert_eq!(contains_shell_syntax("/usr/bin/env", "/usr/bin/env"), true);
        assert_eq!(contains_shell_syntax("/bin/ps", "/bin/ps"), true);
        //assert_eq!(contains_shell_syntax("/usr/bin/W", "/usr/bin/W"), true);
        assert_eq!(contains_shell_syntax("lsattr", "lsattr"), true);
    }
    #[test]
    fn test_detects_commands_surrounded_by_separators() {
        assert_eq!(
            contains_shell_syntax(
                r#"find /path/to/search -type f -name "pattern" -exec rm {} \; "#,
                "rm"
            ),
            true
        );
    }

    #[test]
    fn test_detects_commands_with_separator_before() {
        assert_eq!(
            contains_shell_syntax(
                r#"find /path/to/search -type f -name "pattern" | xargs rm"#,
                "rm"
            ),
            true
        );
    }

    #[test]
    fn test_detects_commands_with_separator_after() {
        assert!(contains_shell_syntax("rm arg", "rm"));
    }

    #[test]
    fn test_checks_if_same_command_occurs_in_user_input() {
        assert!(!contains_shell_syntax("find cp", "rm"));
    }

    #[test]
    fn test_treats_colon_as_command() {
        assert!(contains_shell_syntax(":|echo", ":|"));
        assert!(!contains_shell_syntax(
            "https://www.google.com",
            "https://www.google.com"
        ));
    }

    #[test]
    fn test_detects_commands_with_separators() {
        assert!(contains_shell_syntax("rm>arg", "rm"));
        assert!(contains_shell_syntax("rm<arg", "rm"));
    }

    #[test]
    fn test_empty_command_and_input() {
        assert!(!contains_shell_syntax("", ""));
        assert!(!contains_shell_syntax("", "rm"));
        assert!(!contains_shell_syntax("rm", ""));
    }

    #[test]
    fn test_command_with_special_characters() {
        assert!(contains_shell_syntax("echo $HOME", "echo"));
        assert!(contains_shell_syntax("echo $HOME", "$HOME"));
        assert!(contains_shell_syntax("echo \"Hello World\"", "echo"));
        assert!(contains_shell_syntax("echo 'Hello World'", "echo"));
    }

    #[test]
    fn test_command_with_multiple_separators() {
        assert!(contains_shell_syntax("rm -rf; echo 'done'", "rm"));
        assert!(contains_shell_syntax("ls | grep 'test'", "ls"));
        assert!(contains_shell_syntax(
            "find . -name '*.txt' | xargs rm",
            "rm"
        ));
    }
    #[test]
    fn test_command_with_path_prefixes() {
        assert!(contains_shell_syntax("/bin/rm -rf /tmp", "/bin/rm"));
        assert!(contains_shell_syntax(
            "/usr/bin/killall process_name",
            "/usr/bin/killall"
        ));
        assert!(contains_shell_syntax(
            "/sbin/shutdown now",
            "/sbin/shutdown"
        ));
    }

    #[test]
    fn test_command_with_colon() {
        assert!(contains_shell_syntax(":; echo 'test'", ":"));
        assert!(contains_shell_syntax("echo :; echo 'test'", ":"));
    }
    #[test]
    fn test_command_with_newline_separators() {
        assert!(contains_shell_syntax("echo 'Hello'\nrm -rf /tmp", "rm"));
        assert!(contains_shell_syntax("echo 'Hello'\n", "echo"));
    }

    #[test]
    fn test_command_with_tabs() {
        assert!(contains_shell_syntax("echo 'Hello'\trm -rf /tmp", "rm"));
        assert!(contains_shell_syntax("\techo 'Hello'", "echo"));
    }

    #[test]
    fn test_command_with_invalid_input() {
        assert!(!contains_shell_syntax("echo 'Hello'", "invalid_command"));
        assert!(!contains_shell_syntax("ls -l", "rm"));
    }

    #[test]
    fn test_command_with_multiple_commands() {
        assert!(contains_shell_syntax("rm -rf; ls -l; echo 'done'", "ls"));
        assert!(contains_shell_syntax("echo 'Hello'; rm -rf /tmp", "rm"));
    }
    #[test]
    fn test_command_with_no_separators() {
        assert!(!contains_shell_syntax("echoHello", "echo"));
        assert!(!contains_shell_syntax("rmrf", "rm"));
    }

    #[test]
    fn test_command_with_dangerous_chars() {
        assert!(contains_shell_syntax("rm -rf; echo 'done'", ";"));
        assert!(contains_shell_syntax("echo 'Hello' & rm -rf /tmp", "&"));
        assert!(contains_shell_syntax("echo 'Hello' | rm -rf /tmp", "|"));
    }

    #[test]
    fn test_command_with_path_and_arguments() {
        assert!(contains_shell_syntax("/usr/bin/ls -l", "/usr/bin/ls"));
        assert!(contains_shell_syntax("/bin/cp file1 file2", "/bin/cp"));
    }
}
