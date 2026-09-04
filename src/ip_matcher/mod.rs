// Exact port of firewall-node's core matcher, including its parsing behavior.
// Based on https://github.com/demskie/netparser (MIT, Copyright (c) 2019 alex).

use std::cmp::Ordering;

const IPV4_BYTES: u8 = 4;
const IPV6_BYTES: u8 = 16;

#[derive(Clone, Eq, PartialEq)]
struct Network {
    byte_length: u8,
    bytes: [u8; 16],
    cidr: u8,
}

impl Network {
    fn contains(&self, other: &Self) -> bool {
        if self.byte_length != other.byte_length {
            return false;
        }
        if self.cidr == 0 {
            return true;
        }
        if other.cidr == 0
            || self.cidr > other.cidr
            || compare_addresses(self, other) == Ordering::Greater
        {
            return false;
        }

        let complete_bytes = usize::from(self.cidr / 8);
        if self.bytes[..complete_bytes] != other.bytes[..complete_bytes] {
            return false;
        }

        let remaining_bits = self.cidr % 8;
        if remaining_bits == 0 {
            return true;
        }
        let mask = u8::MAX << (8 - remaining_bits);
        self.bytes[complete_bytes] & mask == other.bytes[complete_bytes] & mask
    }

    fn is_base_address(&self, cidr: i16) -> bool {
        if cidr < 0 || cidr > i16::from(self.byte_length) * 8 {
            return false;
        }

        let mut masked = self.clone();
        masked.cidr = cidr as u8;
        masked.apply_subnet_mask();
        self.bytes == masked.bytes
    }

    fn apply_subnet_mask(&mut self) {
        let complete_bytes = usize::from(self.cidr / 8);
        let remaining_bits = self.cidr % 8;
        let first_zero_byte = if remaining_bits == 0 {
            complete_bytes
        } else {
            self.bytes[complete_bytes] &= u8::MAX << (8 - remaining_bits);
            complete_bytes + 1
        };

        self.bytes[first_zero_byte..usize::from(self.byte_length)].fill(0);
    }

    fn next(&self) -> Option<Self> {
        if self.cidr == 0 {
            return None;
        }

        let mut next = self.clone();
        match self.byte_length {
            IPV4_BYTES => {
                let value = u32::from_be_bytes(self.bytes[..4].try_into().ok()?);
                let increment = 1_u32 << (32 - self.cidr);
                next.bytes[..4].copy_from_slice(&value.checked_add(increment)?.to_be_bytes());
            }
            IPV6_BYTES => {
                let value = u128::from_be_bytes(self.bytes);
                let increment = 1_u128 << (128 - self.cidr);
                next.bytes = value.checked_add(increment)?.to_be_bytes();
            }
            _ => return None,
        }
        Some(next)
    }

    fn adjacent(&self, other: &Self) -> bool {
        if self.byte_length != other.byte_length {
            return false;
        }
        if self.cidr == 0 || other.cidr == 0 {
            return true;
        }

        let (first, second) = if compare_addresses(self, other) == Ordering::Less {
            (self, other)
        } else {
            (other, self)
        };
        first
            .next()
            .is_some_and(|next| compare_addresses(&next, second) == Ordering::Equal)
    }
}

impl Ord for Network {
    fn cmp(&self, other: &Self) -> Ordering {
        compare_addresses(self, other).then_with(|| self.cidr.cmp(&other.cidr))
    }
}

impl PartialOrd for Network {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

fn compare_addresses(left: &Network, right: &Network) -> Ordering {
    left.byte_length.cmp(&right.byte_length).then_with(|| {
        left.bytes[..usize::from(left.byte_length)]
            .cmp(&right.bytes[..usize::from(right.byte_length)])
    })
}

pub struct IpMatcher {
    sorted: Vec<Network>,
}

impl IpMatcher {
    pub fn new<I, S>(networks: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let networks = networks.into_iter();
        let mut subnets = Vec::with_capacity(networks.size_hint().1.unwrap_or(0).min(1024));
        for network in networks {
            if let Some(network) = parse_base_network(network.as_ref()) {
                subnets.push(network);
            }
        }

        subnets.sort_unstable();
        Self {
            sorted: summarize_sorted_networks(subnets),
        }
    }

    pub fn memory_size(&self) -> usize {
        std::mem::size_of::<Self>() + self.sorted.capacity() * std::mem::size_of::<Network>()
    }

    pub fn has(&self, network: &str) -> bool {
        if let Some(bytes) = parse_strict_ipv4_address(network) {
            return self.has_ipv4(&bytes);
        }

        let Some(network) = parse_base_network(network) else {
            return false;
        };
        let index = self
            .sorted
            .partition_point(|candidate| candidate <= &network);
        self.sorted
            .get(index)
            .is_some_and(|candidate| candidate.contains(&network))
            || index
                .checked_sub(1)
                .and_then(|previous| self.sorted.get(previous))
                .is_some_and(|candidate| candidate.contains(&network))
    }

    fn has_ipv4(&self, bytes: &[u8; 16]) -> bool {
        let address = ipv4_value(bytes);
        let index = self.sorted.partition_point(|candidate| {
            candidate.byte_length < IPV4_BYTES
                || (candidate.byte_length == IPV4_BYTES && ipv4_value(&candidate.bytes) <= address)
        });

        let Some(candidate) = index
            .checked_sub(1)
            .and_then(|previous| self.sorted.get(previous))
            .filter(|candidate| candidate.byte_length == IPV4_BYTES)
        else {
            return false;
        };
        if candidate.cidr == 0 {
            return true;
        }

        address >> (32 - candidate.cidr) == ipv4_value(&candidate.bytes) >> (32 - candidate.cidr)
    }
}

fn summarize_sorted_networks(sorted: Vec<Network>) -> Vec<Network> {
    let mut summarized: Vec<Network> = Vec::with_capacity(sorted.len());
    for network in sorted {
        if summarized
            .last()
            .is_some_and(|candidate| candidate.contains(&network))
        {
            continue;
        }

        summarized.push(network);
        while summarized.len() >= 2 {
            let second_index = summarized.len() - 1;
            let first_index = second_index - 1;
            let first = &summarized[first_index];
            let second = &summarized[second_index];
            if first.cidr != second.cidr
                || !first.is_base_address(i16::from(first.cidr) - 1)
                || !first.adjacent(second)
            {
                break;
            }

            summarized[first_index].cidr -= 1;
            summarized[first_index].apply_subnet_mask();
            summarized.pop();
        }
    }
    summarized
}

fn parse_base_network(value: &str) -> Option<Network> {
    let mut network = parse_network(value)?;
    network.apply_subnet_mask();
    Some(network)
}

fn parse_network(value: &str) -> Option<Network> {
    let value = trim_ascii_whitespace(value);
    let mut parts = value.split('/');
    let address = parts.next()?;
    let cidr = parts.next();
    if parts.next().is_some() {
        return None;
    }

    let is_ipv4 = looks_like_ipv4(value)?;
    let byte_length = if is_ipv4 { IPV4_BYTES } else { IPV6_BYTES };
    let max_cidr = byte_length * 8;
    let cidr = match cidr {
        Some(cidr) => parse_int_range(cidr, max_cidr)?,
        None => max_cidr,
    };

    let mut bytes = [0; 16];
    let parsed = if is_ipv4 {
        parse_ipv4(address, &mut bytes)
    } else {
        parse_ipv6(address, &mut bytes)
    };
    parsed.then_some(Network {
        byte_length,
        bytes,
        cidr,
    })
}

fn is_ascii_whitespace(byte: u8) -> bool {
    matches!(byte, b' ' | b'\t' | b'\n' | b'\r' | 0x0c | 0x0b)
}

fn trim_ascii_whitespace(value: &str) -> &str {
    let bytes = value.as_bytes();
    let mut start = 0;
    while start < bytes.len() && is_ascii_whitespace(bytes[start]) {
        start += 1;
    }

    let mut end = bytes.len();
    while end > start && is_ascii_whitespace(bytes[end - 1]) {
        end -= 1;
    }
    &value[start..end]
}

fn parse_int10(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index < bytes.len() && is_ascii_whitespace(bytes[index]) {
        index += 1;
    }

    let mut negative = false;
    if let Some(sign) = bytes.get(index).filter(|sign| matches!(sign, b'+' | b'-')) {
        negative = *sign == b'-';
        index += 1;
    }

    let start = index;
    let mut number = 0_u64;
    while let Some(digit) = bytes
        .get(index)
        .copied()
        .filter(|digit| digit.is_ascii_digit())
    {
        number = number
            .checked_mul(10)?
            .checked_add(u64::from(digit - b'0'))?;
        index += 1;
    }
    if index == start || number > i64::MAX as u64 {
        return None;
    }

    let number = number as i64;
    Some(if negative { -number } else { number })
}

fn parse_int_range(value: &str, max: u8) -> Option<u8> {
    let mut number = 0_u32;
    let mut digits = 0;
    for byte in value.bytes().take_while(u8::is_ascii_digit) {
        number = number
            .checked_mul(10)?
            .checked_add(u32::from(byte - b'0'))?;
        digits += 1;
        if number > u32::from(max) {
            return None;
        }
    }

    (digits > 0 && number <= u32::from(max)).then_some(number as u8)
}

fn looks_like_ipv4(value: &str) -> Option<bool> {
    for byte in value.bytes() {
        match byte {
            b'.' => return Some(true),
            b':' => return Some(false),
            _ => {}
        }
    }
    None
}

fn parse_ipv4(value: &str, bytes: &mut [u8; 16]) -> bool {
    let mut parts = value.split('.');
    for byte in bytes.iter_mut().take(4) {
        let Some(parsed) = parts.next().and_then(parse_int10) else {
            return false;
        };
        if !(0..=255).contains(&parsed) {
            return false;
        }
        *byte = parsed as u8;
    }
    parts.next().is_none()
}

fn parse_strict_ipv4_address(value: &str) -> Option<[u8; 16]> {
    let input = value.as_bytes();
    let mut bytes = [0; 16];
    let mut position = 0;

    for (index, output) in bytes.iter_mut().take(4).enumerate() {
        let start = position;
        let mut number = 0_u16;
        while let Some(digit) = input
            .get(position)
            .copied()
            .filter(|digit| digit.is_ascii_digit())
        {
            number = number * 10 + u16::from(digit - b'0');
            if number > 255 {
                return None;
            }
            position += 1;
        }
        if position == start {
            return None;
        }
        *output = number as u8;

        if index < 3 {
            if input.get(position) != Some(&b'.') {
                return None;
            }
            position += 1;
        }
    }
    (position == input.len()).then_some(bytes)
}

fn ipv4_value(bytes: &[u8; 16]) -> u32 {
    u32::from_be_bytes(bytes[..4].try_into().expect("IPv4 has four bytes"))
}

fn parse_hextet(value: &str) -> Option<u16> {
    let trimmed = trim_ascii_whitespace(value);
    if trimmed.is_empty() || trimmed.len() > 4 {
        return None;
    }

    let mut parsed = 0_u16;
    for byte in value.bytes() {
        let digit = match byte {
            b'0'..=b'9' => u16::from(byte - b'0'),
            b'a'..=b'f' => u16::from(byte - b'a' + 10),
            b'A'..=b'F' => u16::from(byte - b'A' + 10),
            _ => return None,
        };
        parsed = parsed * 16 + digit;
    }
    Some(parsed)
}

fn remove_brackets(value: &str) -> &str {
    if !value.starts_with('[') {
        return value;
    }

    value
        .rfind(']')
        .map_or(value, |closing_bracket| &value[1..closing_bracket])
}

fn remove_port_info(value: &str) -> &str {
    value
        .find(['#', 'p', '.'])
        .map_or(value, |index| trim_ascii_whitespace(&value[..index]))
}

fn has_four_ipv4_parts(value: &str) -> bool {
    let mut parts = value.split('.');
    (0..4).all(|_| parts.next().is_some()) && parts.next().is_none()
}

fn parse_ipv4_part(
    value: &str,
    bytes: &mut [u8; 16],
    byte_index: &mut isize,
    reverse: bool,
) -> bool {
    let mut split = value.split('.');
    let mut parts = [""; 4];
    for part in &mut parts {
        let Some(value) = split.next() else {
            return false;
        };
        *part = value;
    }
    if split.next().is_some() {
        return false;
    }

    for offset in 0..4 {
        let index = if reverse { 3 - offset } else { offset };
        let Some(parsed) = parse_int10(parts[index]) else {
            return false;
        };
        if !(0..=255).contains(&parsed) || !(0..16).contains(byte_index) {
            return false;
        }
        bytes[*byte_index as usize] = parsed as u8;
        *byte_index += if reverse { -1 } else { 1 };
    }
    true
}

fn parse_ipv6_left_half(bytes: &mut [u8; 16], value: &str, byte_index: &mut isize) -> bool {
    if value.is_empty() {
        return true;
    }

    for part in value.split(':') {
        if *byte_index >= 16 {
            return false;
        }
        if has_four_ipv4_parts(part) {
            if !parse_ipv4_part(part, bytes, byte_index, false) {
                return false;
            }
            continue;
        }

        let Some(parsed) = parse_hextet(part) else {
            return false;
        };
        if *byte_index + 1 >= 16 {
            return false;
        }
        bytes[*byte_index as usize] = (parsed / 256) as u8;
        *byte_index += 1;
        bytes[*byte_index as usize] = (parsed % 256) as u8;
        *byte_index += 1;
    }
    true
}

fn parse_ipv6_right_half(bytes: &mut [u8; 16], value: &str, left_byte_index: isize) -> bool {
    if value.is_empty() {
        return true;
    }

    let mut right_byte_index = 15_isize;
    for (offset, mut part) in value.rsplit(':').enumerate() {
        if trim_ascii_whitespace(part).is_empty() || left_byte_index > right_byte_index {
            return false;
        }
        if has_four_ipv4_parts(part) {
            if !parse_ipv4_part(part, bytes, &mut right_byte_index, true) {
                return false;
            }
            continue;
        }
        if offset == 0 {
            part = remove_port_info(part);
        }

        let Some(parsed) = parse_hextet(part) else {
            return false;
        };
        if right_byte_index - 1 < 0 {
            return false;
        }
        bytes[right_byte_index as usize] = (parsed % 256) as u8;
        right_byte_index -= 1;
        bytes[right_byte_index as usize] = (parsed / 256) as u8;
        right_byte_index -= 1;
    }
    true
}

fn parse_ipv6(value: &str, bytes: &mut [u8; 16]) -> bool {
    let value = remove_brackets(value);
    if value.is_empty() {
        return false;
    }
    if value == "::" {
        return true;
    }

    let split_index = value.find("::");
    if split_index.is_some_and(|index| value[index + 2..].contains("::")) {
        return false;
    }

    let left_length = split_index.unwrap_or(value.len());
    let mut left_byte_index = 0;
    if !parse_ipv6_left_half(bytes, &value[..left_length], &mut left_byte_index) {
        return false;
    }

    match split_index {
        Some(index) => parse_ipv6_right_half(bytes, &value[index + 2..], left_byte_index),
        None => true,
    }
}

#[cfg(test)]
mod ip_matcher_test;
