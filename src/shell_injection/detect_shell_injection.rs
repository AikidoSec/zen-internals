use super::contains_shell_syntax::contains_shell_syntax;
use super::is_safely_encapsulated::is_safely_encapsulated;

pub fn detect_shell_injection_stringified(command: &str, user_input: &str) -> bool {
    if user_input == "~" && command.len() > 1 && command.contains("~") {
        // Block single ~ character. For example echo ~
        return true;
    }

    if user_input.len() <= 1 {
        // We ignore single characters since they don't pose a big threat.
        // They are only able to crash the shell, not execute arbitrary commands.
        return false;
    }

    if user_input.len() > command.len() {
        // We ignore cases where the user input is longer than the command.
        // Because the user input can't be part of the command.
        return false;
    }

    if !command.contains(user_input) {
        return false;
    }

    if is_safely_encapsulated(command, user_input) {
        return false;
    }

    contains_shell_syntax(command, user_input)
}
