// First 19 entries are unix root folders, last two entries are for Windows/MS-DOS.
const DANGEROUS_PATH_STARTS: [&str; 21] = [
    "/bin/", "/boot/", "/dev/", "/etc/", "/home/", "/init/", "/lib/", "/media/", "/mnt/", "/opt/",
    "/proc/", "/root/", "/run/", "/sbin/", "/srv/", "/sys/", "/tmp/", "/usr/", "/var/", "c:/",
    "c:\\",
];

pub fn starts_with_unsafe_path(file_path: &str, user_input: &str) -> bool {
    let lower_case_path = file_path.to_lowercase();
    let lower_case_user_input = user_input.to_lowercase();

    for dangerous_start in &DANGEROUS_PATH_STARTS {
        if lower_case_path.starts_with(dangerous_start)
            && lower_case_path.starts_with(&lower_case_user_input)
        {
            return true;
        }
    }

    false
}
