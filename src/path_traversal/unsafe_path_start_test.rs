#[cfg(test)]
mod tests {
    use crate::path_traversal::unsafe_path_start::starts_with_unsafe_path;

    #[test]
    fn test_linux_root_paths() {
        assert!(starts_with_unsafe_path("/etc/passwd", "/etc"));
        assert!(starts_with_unsafe_path("/bin/bash", "/bin"));
        assert!(starts_with_unsafe_path("/lib/modules", "/lib"));
        assert!(starts_with_unsafe_path("/home/user/file.txt", "/home"));
        assert!(starts_with_unsafe_path("/usr/local/bin", "/usr"));
        assert!(starts_with_unsafe_path("/var/log/syslog", "/var"));
    }

    #[test]
    fn test_windows_paths() {
        assert!(starts_with_unsafe_path("c:/Program Files/app.exe", "c:/"));
        assert!(starts_with_unsafe_path(
            "c:\\Windows\\System32\\cmd.exe",
            "c:\\"
        ));
        assert!(!starts_with_unsafe_path("d:/Documents/file.txt", "c:/"));
    }

    #[test]
    fn test_edge_cases() {
        assert!(!starts_with_unsafe_path("", "/etc"));
        assert!(!starts_with_unsafe_path("/etc", ""));
        assert!(starts_with_unsafe_path("c:/", "c:/"));
        assert!(starts_with_unsafe_path("c:/folder/file.txt", "c:/folder"));
    }
}
