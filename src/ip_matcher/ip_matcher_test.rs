use super::IpMatcher;

fn assert_cases(networks: &[&str], cases: &[(&str, bool)]) {
    let matcher = IpMatcher::new(networks.iter().copied());
    for &(lookup, expected) in cases {
        assert_eq!(
            matcher.has(lookup),
            expected,
            "unexpected result for {lookup:?}"
        );
    }
}
