use std::ffi::CStr;
use std::os::raw::{c_char, c_int};
use std::str;
use super::contains_shell_syntax::contains_shell_syntax;
use super::is_safely_encapsulated::is_safely_encapsulated;

#[no_mangle]
pub extern "C"   fn detect_shell_injection(command: *const c_char, userinput: *const c_char) -> c_int {
    // Check if the pointers are null
    if command.is_null() || userinput.is_null() {
        eprintln!("Received null pointer for command or userinput.");
        return 0; // Handle the error as needed
    }
    let command_bytes = unsafe { CStr::from_ptr(command).to_bytes() };
    let userinput_bytes = unsafe { CStr::from_ptr(userinput).to_bytes() };


    let command_str = str::from_utf8(command_bytes).unwrap();
    let userinput_str = str::from_utf8(userinput_bytes).unwrap();
    println!("Command : {} And userinput : {}", command_str, userinput_str);
    if detect_shell_injection_stringified(command_str, userinput_str) {
        return 1;
    }
    0
}

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