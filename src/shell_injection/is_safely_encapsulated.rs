// Function to get current and next segments
fn get_current_and_next_segments(array: Vec<&str>) -> Vec<(&str, &str)> {
    // Create a vector to hold the segments
    let mut segments = Vec::new();

    // Iterate over the indices of the array, stopping before the last element
    for i in 0..array.len() - 1 {
        // Push a tuple of the current and next elements into the segments vector
        segments.push((array[i], array[i + 1]));
    }

    segments
}

// Constants for escape characters and dangerous characters
const ESCAPE_CHARS: [&str; 2] = ["\"", "'"];
const DANGEROUS_CHARS_INSIDE_DOUBLE_QUOTES: [&str; 4] = ["$", "`", "\\", "!"];

// Function to check if user input is safely encapsulated
pub fn is_safely_encapsulated(command: &str, user_input: &str) -> bool {
    let segments = get_current_and_next_segments(command.split(user_input).collect());

    for (current_segment, next_segment) in segments {
        let char_before_user_input = current_segment.chars().last();
        let char_after_user_input = next_segment.chars().next();

        let is_escape_char = char_before_user_input
            .map_or(false, |c| ESCAPE_CHARS.contains(&c.to_string().as_str()));

        if !is_escape_char {
            return false;
        }

        if char_before_user_input != char_after_user_input {
            return false;
        }

        if char_before_user_input.map_or(false, |c| user_input.contains(c)) {
            return false;
        }

        // Check for dangerous characters inside double quotes
        if char_before_user_input == Some('"') {
            if user_input
                .chars()
                .any(|c| DANGEROUS_CHARS_INSIDE_DOUBLE_QUOTES.contains(&c.to_string().as_str()))
            {
                return false;
            }
        }
    }

    true
}
