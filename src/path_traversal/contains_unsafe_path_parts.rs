const DANGEROUS_PATH_PARTS: [&str; 2] = ["../", "..\\"];

/// Check if the file path contains any dangerous path parts.
pub fn contains_unsafe_path_parts(file_path: &str) -> bool {
    for dangerous_part in DANGEROUS_PATH_PARTS.iter() {
        if file_path.contains(dangerous_part) {
            return true;
        }
    }
    false
}
