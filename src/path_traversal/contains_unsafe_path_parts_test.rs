#[cfg(test)]
mod tests {
    use crate::path_traversal::contains_unsafe_path_parts::contains_unsafe_path_parts;

    #[test]
    fn test_safe_paths() {
        assert!(!contains_unsafe_path_parts("/home/user/file.txt"));
        assert!(!contains_unsafe_path_parts(
            "C:\\Users\\User\\Documents\\file.txt"
        ));
        assert!(!contains_unsafe_path_parts("C:/Program Files/app.exe"));
    }

    #[test]
    fn test_dangerous_paths() {
        assert!(contains_unsafe_path_parts("/home/user/../file.txt"));
        assert!(contains_unsafe_path_parts(
            "C:\\Users\\User\\..\\Documents\\file.txt"
        ));
        assert!(contains_unsafe_path_parts("..\\..\\file.txt"));
        assert!(contains_unsafe_path_parts("../folder/file.txt"));
    }

    #[test]
    fn test_edge_cases() {
        assert!(!contains_unsafe_path_parts(""));
        assert!(!contains_unsafe_path_parts(".."));
        assert!(!contains_unsafe_path_parts("."));
        assert!(contains_unsafe_path_parts("folder/../file.txt"));
        assert!(contains_unsafe_path_parts("folder\\..\\file.txt"));
    }
}
