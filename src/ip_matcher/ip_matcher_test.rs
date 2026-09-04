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
fn check_with_single_ipv4s() {
    assert_cases(
        &[
            "192.168.0.0/32",
            "192.168.0.3/32",
            "192.168.0.24/32",
            "192.168.0.52/32",
            "192.168.0.123/32",
            "192.168.0.124/32",
            "192.168.0.125/32",
            "192.168.0.170/32",
            "192.168.0.171/32",
            "192.168.0.222/32",
            "192.168.0.234/32",
            "192.168.0.255/32",
        ],
        &[
            ("192.168.0.254", false),
            ("192.168.0.1", false),
            ("192.168.0.255", true),
            ("192.168.0.24", true),
        ],
    );
}

#[test]
fn it_works_with_ranges() {
    assert_cases(
        &[
            "192.168.0.0/24",
            "192.168.0.3/32",
            "192.168.0.24/32",
            "192.168.0.52/32",
            "192.168.0.123/32",
            "192.168.0.124/32",
            "192.168.0.125/32",
            "192.168.0.170/32",
            "192.168.0.171/32",
            "192.168.0.222/32",
            "192.168.0.234/32",
            "192.168.0.255/32",
        ],
        &[
            ("192.168.0.254", true),
            ("10.0.0.1", false),
            ("192.168.0.234", true),
        ],
    );
}

#[test]
fn it_works_with_invalid_ranges() {
    assert_cases(
        &[
            "192.168.0.0/24",
            "192.168.0.3/32",
            "192.168.0.24/32",
            "192.168.0.52/32",
            "foobar",
            "0.a.0.0/32",
            "123.123.123.123/1999",
            "",
            ",,,",
            "192.168.0.124/32",
            "192.168.0.125/32",
            "192.168.0.170/32",
            "192.168.0.171/32",
            "192.168.0.222/32",
            "192.168.0.234/32",
            "192.168.0.255",
        ],
        &[
            ("192.168.0.254", true),
            ("foobar", false),
            ("192.168.0.222", true),
            ("192.168.0.1", true),
            ("10.0.0.1", false),
            ("192.168.0.255", true),
            ("", false),
            ("1", false),
            ("192.168.0.1/32", true),
        ],
    );
}

#[test]
fn it_accepts_port_suffixed_ipv4_lookups() {
    assert_cases(&["192.0.2.1"], &[("192.0.2.1:80", true)]);
}

#[test]
fn it_works_with_empty_ranges() {
    assert_cases(&[], &[("192.168.2.1", false), ("foobar", false)]);
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
fn mix_ipv4_and_ipv6() {
    assert_cases(
        &["2002:db8::/32", "10.0.0.0/8"],
        &[
            ("2001:db8::1", false),
            ("2001:db8::0", false),
            ("2002:db8::1", true),
            ("10.0.0.1", true),
            ("10.0.0.255", true),
            ("192.168.1.1", false),
        ],
    );
}

#[test]
fn strange_ips() {
    assert_cases(
        &["::ffff:0.0.0.0", "::ffff:0:0:0:0", "::ffff:127.0.0.1"],
        &[
            ("::ffff:0.0.0.0", true),
            ("::ffff:127.0.0.1", true),
            ("::ffff:123", false),
            ("2001:db8::1", false),
            ("[::ffff:0.0.0.0]", true),
            ("::ffff:0:0:0:0", true),
        ],
    );
}

#[test]
fn different_cidr_ranges() {
    let tests = [
        ("123.2.0.2/0", "1.1.1.1", true),
        ("123.2.0.2/1", "1.1.1.1", true),
        ("123.2.0.2/2", "1.1.1.1", false),
        ("123.2.0.2/3", "123.3.0.1", true),
        ("123.2.0.2/4", "123.3.0.1", true),
        ("123.2.0.2/5", "123.3.0.1", true),
        ("123.2.0.2/6", "123.3.0.1", true),
        ("123.2.0.2/7", "123.3.0.1", true),
        ("123.2.0.2/8", "123.3.0.1", true),
        ("123.2.0.2/9", "123.3.0.1", true),
        ("123.2.0.2/10", "123.3.0.1", true),
        ("123.2.0.2/11", "123.3.0.1", true),
        ("123.2.0.2/12", "123.3.0.1", true),
        ("123.2.0.2/13", "123.3.0.1", true),
        ("123.2.0.2/14", "123.3.0.1", true),
        ("123.2.0.2/15", "123.3.0.1", true),
        ("123.2.0.2/16", "123.3.0.1", false),
        ("123.2.0.2/17", "123.2.0.1", true),
        ("123.2.0.2/18", "123.2.0.1", true),
        ("123.2.0.2/19", "123.2.0.1", true),
        ("123.2.0.2/20", "123.2.0.1", true),
        ("123.2.0.2/21", "123.2.0.1", true),
        ("123.2.0.2/22", "123.2.0.1", true),
        ("123.2.0.2/23", "123.2.0.1", true),
        ("123.2.0.2/24", "123.2.0.1", true),
        ("123.2.0.2/25", "123.2.0.1", true),
        ("123.2.0.2/26", "123.2.0.1", true),
        ("123.2.0.2/27", "123.2.0.1", true),
        ("123.2.0.2/29", "123.2.0.1", true),
        ("123.2.0.2/30", "123.2.0.1", true),
        ("123.2.0.2/31", "123.2.0.1", false),
        ("123.2.0.2/32", "123.2.0.2", true),
    ];

    for &(network, address, expected) in &tests {
        assert_cases(&[network], &[(address, expected)]);
    }
}

#[test]
fn allow_all_ips() {
    assert_cases(
        &["0.0.0.0/0", "::/0"],
        &[
            ("1.2.3.4", true),
            ("::1", true),
            ("::ffff:1234", true),
            ("1.1.1.1", true),
            ("2002:db8::1", true),
            ("10.0.0.1", true),
            ("10.0.0.255", true),
            ("192.168.1.1", true),
        ],
    );
}

#[test]
fn adjacent_4_ranges_at_end_of_address_space() {
    assert_cases(
        &["224.0.0.0/4", "240.0.0.0/4"],
        &[
            ("224.0.0.1", true),
            ("240.0.0.1", true),
            ("255.255.255.255", true),
            ("223.255.255.255", false),
        ],
    );
}

#[test]
fn matches_mixed_networks_and_ignores_invalid_entries() {
    assert_cases(
        &[
            "192.168.0.123/24",
            "2001:db8:1::beef/48",
            "[2001:db8::f]",
            "not-an-address",
            "0.a.0.0/32",
            "123.123.123.123/1999",
            "",
        ],
        &[
            ("192.168.0.1", true),
            ("192.168.0.42:443", true),
            ("192.168.0.128/25", true),
            ("192.168.0.0/16", false),
            ("192.168.1.1", false),
            ("2001:db8:1:ffff::1", true),
            ("2001:db8:2::1", false),
            ("2001:db8::f", true),
            ("[2001:db8::f]", true),
            ("not-an-address", false),
            ("192.168.0.999", false),
            ("", false),
        ],
    );
}

#[test]
fn preserves_embedded_ipv4_and_mapped_address_forms() {
    assert_cases(
        &[
            "64:ff9b::192.0.2.1",
            "::ffff:127.0.0.1",
            "::ffff:0.0.0.0",
            "::ffff:0:0:0:0",
            "192.0.2.55",
        ],
        &[
            ("64:ff9b::c000:201", true),
            ("[::ffff:127.0.0.1]", true),
            ("::ffff:7f00:1", true),
            ("::ffff:0.0.0.0", true),
            ("::ffff:0:0:0:0", true),
            ("127.0.0.1", false),
            ("::ffff:192.0.2.55", false),
            ("::ffff:123", false),
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
