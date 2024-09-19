use regex::{Regex, RegexBuilder};

// Constants
const DANGEROUS_CHARS: [&str; 26] = [
    "#",
    "!",
    "\"",
    "$",
    "&",
    "'",
    "(",
    ")",
    "*",
    ";",
    "<",
    "=",
    ">",
    "?",
    "[",
    "\\",
    "]",
    "^",
    "`",
    "{",
    "|",
    "}",
    " ",
    "\n",
    "\t",
    "~",
];
const COMMANDS: [&str; 61] = [
    "sleep",
    "shutdown",
    "reboot",
    "poweroff",
    "halt",
    "ifconfig",
    "chmod",
    "chown",
    "ping",
    "ssh",
    "scp",
    "curl",
    "wget",
    "telnet",
    "kill",
    "killall",
    "rm",
    "mv",
    "cp",
    "touch",
    "echo",
    "cat",
    "head",
    "tail",
    "grep",
    "find",
    "awk",
    "sed",
    "sort",
    "uniq",
    "wc",
    "ls",
    "env",
    "ps",
    "who",
    "whoami",
    "id",
    "w",
    "df",
    "du",
    "pwd",
    "uname",
    "hostname",
    "netstat",
    "passwd",
    "arch",
    "printenv",
    "logname",
    "pstree",
    "hostnamectl",
    "set",
    "lsattr",
    "killall5",
    "dmesg",
    "history",
    "free",
    "uptime",
    "finger",
    "top",
    "shopt",
    ":",  // Colon is a null command
];
const PATH_PREFIXES: [&str; 6] = [
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
];
const SEPARATORS: [&str; 10] = [" ", "\t", "\n", ";", "&", "|", "(", ")", "<", ">"];

fn create_commands_regex() -> Regex {
    // Escape path prefixes and join them
    let path_prefixes_pattern = PATH_PREFIXES.iter().map(|s| regex::escape(s)).collect::<Vec<_>>().join("|");
    
    // Sort commands by length in descending order and escape them
    let mut sorted_commands = COMMANDS.to_vec();
    sorted_commands.sort_by_key(|b| std::cmp::Reverse(b.len())); // Sort by length, descending
    let commands_pattern = sorted_commands.iter().map(|s| regex::escape(s)).collect::<Vec<_>>().join("|");
    
    // Create the regex pattern
    let pattern = format!(r"([/.]*({})?({}))", path_prefixes_pattern, commands_pattern);
    
    // Create the regex with case insensitive and multiline flags
    RegexBuilder::new(&pattern)
        .case_insensitive(true)
        .multi_line(true)
        .build()
        .unwrap()
}


// Function to check if the user input contains shell syntax given the command
pub fn contains_shell_syntax(command: &str, user_input: &str) -> bool {
    let commands_regex = create_commands_regex();

    if user_input.trim().is_empty() {
        // The entire user input is just whitespace, ignore
        return false;
    }

    if DANGEROUS_CHARS.iter().any(|&c| user_input.contains(c)) {
        return true;
    }

    // The command is the same as the user input
    if command == user_input {
        // Check if the command matches the regex
        if let Some(m) = commands_regex.find(command) {
            return m.start() == 0 && m.end() == command.len();
        }
        return false;
    }

    // Check if the command contains a commonly used command
    for mat in commands_regex.captures_iter(command) {
        let matched_command = &mat[0];
        // We found a command like `rm` or `/sbin/shutdown` in the command
        // Check if the command is the same as the user input
        if user_input != matched_command {
            continue;
        }

        // Check surrounding characters
        let start_index = mat.get(0).unwrap().start();
        let end_index = mat.get(0).unwrap().end();

        let char_before = if start_index > 0 {
            command.chars().nth(start_index - 1)
        } else {
            None
        };

        let char_after = if end_index < command.len() {
            command.chars().nth(end_index)
        } else {
            None
        };


        // Check surrounding characters
        if char_before.map_or(false, |c| SEPARATORS.contains(&c.to_string().as_str())) &&
           char_after.map_or(false, |c| SEPARATORS.contains(&c.to_string().as_str())) {
            return true; // e.g. `<separator>rm<separator>`
        }
        if char_before.map_or(false, |c| SEPARATORS.contains(&c.to_string().as_str())) && char_after.is_none() {
            return true; // e.g. `<separator>rm`
        }
        if char_before.is_none() && char_after.map_or(false, |c| SEPARATORS.contains(&c.to_string().as_str())) {
            return true; // e.g. `rm<separator>`
        }
    }
    false
}
