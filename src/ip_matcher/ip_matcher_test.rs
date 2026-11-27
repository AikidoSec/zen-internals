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

#[test]
fn memory_size_includes_network_storage() {
    let empty = IpMatcher::new([] as [&str; 0]);
    let matcher = IpMatcher::new(["192.0.2.1"]);

    assert!(matcher.memory_size() > empty.memory_size());
}

#[test]
fn it_works_with_ipv6_ranges() {
    assert_cases(
        &[
            "2002:db8::/32",
            "2001:db8::1/128",
            "2001:db8::2/128",
            "2001:db8::3/128",
            "2001:db8::4/128",
            "2001:db8::5/128",
            "2001:db8::6/128",
            "2001:db8::7/128",
            "2001:db8::8/128",
            "2001:db8::9/128",
            "2001:db8::a/128",
            "2001:db8::b/128",
            "2001:db8::c/128",
            "2001:db8::d/128",
            "2001:db8::e/128",
            "[2001:db8::f]",
            "2001:db9::abc",
        ],
        &[
            ("2001:db8::1", true),
            ("2001:db8::0", false),
            ("2001:db8::f", true),
            ("[2001:db8::f]", true),
            ("2001:db8::10", false),
            ("2002:db8::1", true),
            ("2002:db8::2f:2", true),
            ("2001:db9::abc", true),
        ],
    );
}

#[test]
fn merges_adjacent_ranges_at_address_space_boundaries() {
    assert_cases(
        &["224.0.0.0/4", "240.0.0.0/4", "e000::/4", "f000::/4"],
        &[
            ("224.0.0.1", true),
            ("255.255.255.255", true),
            ("223.255.255.255", false),
            ("e000::1", true),
            ("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true),
            ("dfff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false),
        ],
    );
}
