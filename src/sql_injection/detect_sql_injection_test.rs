#[cfg(test)]
mod tests {
    use crate::sql_injection::detect_sql_injection::{detect_sql_injection_str, DetectionReason};

    fn dialect(s: &str) -> i32 {
        match s {
            "mysql" => 8,
            "postgresql" => 9,
            "sqlite" => 12,
            "clickhouse" => 3,
            "generic" => 0,
            _ => panic!("Unknown dialect"),
        }
    }

    fn get_supported_dialects() -> Vec<i32> {
        vec![
            dialect("mysql"),
            dialect("postgresql"),
            dialect("sqlite"),
            dialect("clickhouse"),
            dialect("generic"),
        ]
    }

    macro_rules! is_injection {
        ($query:expr, $input:expr) => {
            for dia in get_supported_dialects().iter() {
                let result = detect_sql_injection_str($query, $input, dia.clone());
                assert!(
                    result.detected,
                    "should be an injection\nquery: {}\ninput: {}\ndialect: {}\nreason: {:?}\n",
                    $query,
                    $input,
                    dia.clone(),
                    result.reason
                )
            }
        };
        ($query:expr, $input:expr, $dialect:expr) => {
            assert!(detect_sql_injection_str($query, $input, $dialect).detected)
        };
    }
    macro_rules! not_injection {
        ($query:expr, $input:expr) => {
            for dia in get_supported_dialects().iter() {
                let result = detect_sql_injection_str($query, $input, dia.clone());
                assert!(
                    !(result.detected),
                    "should not be an injection\nquery: {}\ninput: {}\ndialect: {}\nreason: {:?}\n",
                    $query,
                    $input,
                    dia.clone(),
                    result.reason
                )
            }
        };
        ($query:expr, $input:expr, $dialect:expr) => {
            assert!(!(detect_sql_injection_str($query, $input, $dialect).detected))
        };
    }

}
