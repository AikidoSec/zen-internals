use super::tokenize_shell::{tokenize_shell, ShellToken};
use crate::diff_in_vec_len;

const SPACE_CHAR: char = ' ';

#[derive(Debug)]
pub struct ShellInjectionDetectionResult {
    pub detected: bool,
    pub reason: DetectionReason,
}

#[derive(Debug)]
pub enum DetectionReason {
    // not an injection
    UserInputNotInCommand,
    UserInputTooSmall,
    AllWhitespace,
    FailedToTokenize,
    NoChangesFound,
    // injection
    TokensHaveDelta,
    CommentStructureAltered,
}

pub fn detect_shell_injection_str(command: &str, userinput: &str) -> ShellInjectionDetectionResult {
    // Special case: tilde (~) alone expands to home directory
    if userinput == "~" {
        if command.len() > 1 && command.contains('~') {
            return ShellInjectionDetectionResult {
                detected: true,
                reason: DetectionReason::TokensHaveDelta,
            };
        }
    }

    // Single characters can't execute commands on their own
    if userinput.len() <= 1 {
        return ShellInjectionDetectionResult {
            detected: false,
            reason: DetectionReason::UserInputTooSmall,
        };
    }

    // User input longer than command can't be part of it
    if userinput.len() > command.len() {
        return ShellInjectionDetectionResult {
            detected: false,
            reason: DetectionReason::UserInputNotInCommand,
        };
    }

    // User input must appear in the command
    if !command.contains(userinput) {
        return ShellInjectionDetectionResult {
            detected: false,
            reason: DetectionReason::UserInputNotInCommand,
        };
    }

    // Trim spaces from user input
    let trimmed_userinput = userinput.trim_matches(SPACE_CHAR);

    // All whitespace (spaces, tabs, newlines) after trim
    if trimmed_userinput.chars().all(|c| c.is_ascii_whitespace()) {
        return ShellInjectionDetectionResult {
            detected: false,
            reason: DetectionReason::AllWhitespace,
        };
    }

    if trimmed_userinput.len() <= 1 {
        return ShellInjectionDetectionResult {
            detected: false,
            reason: DetectionReason::UserInputTooSmall,
        };
    }

    // Tokenize the original command
    let tokens = tokenize_shell(command);
    if tokens.is_empty() {
        return ShellInjectionDetectionResult {
            detected: false,
            reason: DetectionReason::FailedToTokenize,
        };
    }

    // Replace user input with safe string of equal length and re-tokenize
    let safe_replace_str = "a".repeat(trimmed_userinput.len());
    let command_without_input = command.replace(trimmed_userinput, &safe_replace_str);
    let tokens_without_input = tokenize_shell(&command_without_input);

    // Compare token counts
    if diff_in_vec_len!(tokens, tokens_without_input) {
        return ShellInjectionDetectionResult {
            detected: true,
            reason: DetectionReason::TokensHaveDelta,
        };
    }

    // Check if comment structure changed
    if have_comments_changed(&tokens, &tokens_without_input) {
        return ShellInjectionDetectionResult {
            detected: true,
            reason: DetectionReason::CommentStructureAltered,
        };
    }

    ShellInjectionDetectionResult {
        detected: false,
        reason: DetectionReason::NoChangesFound,
    }
}

fn have_comments_changed(tokens1: &[ShellToken], tokens2: &[ShellToken]) -> bool {
    let comments1: Vec<&str> = tokens1
        .iter()
        .filter_map(|t| match t {
            ShellToken::Comment(c) => Some(c.as_str()),
            _ => None,
        })
        .collect();

    let comments2: Vec<&str> = tokens2
        .iter()
        .filter_map(|t| match t {
            ShellToken::Comment(c) => Some(c.as_str()),
            _ => None,
        })
        .collect();

    if comments1.len() != comments2.len() {
        return true;
    }

    for (c1, c2) in comments1.iter().zip(comments2.iter()) {
        if c1.len() != c2.len() {
            return true;
        }
    }

    false
}
