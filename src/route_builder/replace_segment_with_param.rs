use crate::route_builder::looks_like_a_secret::looks_like_a_secret;
use regex::{Regex, RegexBuilder};
use std::net::IpAddr;

const UUID_REGEX: &str = r"(?:[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000|ffffffff-ffff-ffff-ffff-ffffffffffff)$";
const NUMBER_REGEX: &str = r"^\d+$";
const DATE_REGEX: &str = r"^\d{4}-\d{2}-\d{2}|\d{2}-\d{2}-\d{4}$";
const EMAIL_REGEX: &str = r"^[a-zA-Z0-9.!#$%&\'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$";
const HASH_REGEX: &str = r"^(?:[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{128})$";
const OBJECT_REGEX: &str = r"^[0-9a-f]{24}$";
const HASH_LENGTHS: [usize; 4] = [32, 40, 64, 128];

pub fn replace_segment_with_param(segment: &str) -> String {
    if segment.is_empty() {
        return segment.to_string();
    }

    let starts_with_number = segment.chars().next().unwrap().is_digit(10);

    if starts_with_number && Regex::new(NUMBER_REGEX).unwrap().is_match(segment) {
        return ":number".to_string();
    }

    if segment.len() == 36 && Regex::new(UUID_REGEX).unwrap().is_match(segment) {
        return ":uuid".to_string();
    }

    let object_regex = RegexBuilder::new(OBJECT_REGEX)
        .case_insensitive(true)
        .build()
        .unwrap();
    if segment.len() == 24 && object_regex.is_match(segment) {
        return ":objectId".to_string();
    }

    if starts_with_number && Regex::new(DATE_REGEX).unwrap().is_match(segment) {
        return ":date".to_string();
    }

    if segment.contains('@') && Regex::new(EMAIL_REGEX).unwrap().is_match(segment) {
        return ":email".to_string();
    }

    if segment.parse::<IpAddr>().is_ok() {
        return ":ip".to_string();
    }

    let hash_regex = RegexBuilder::new(HASH_REGEX)
        .case_insensitive(true)
        .build()
        .unwrap();
    if HASH_LENGTHS.contains(&(segment.len())) && hash_regex.is_match(segment) {
        return ":hash".to_string();
    }

    if looks_like_a_secret(segment) {
        return ":secret".to_string();
    }

    segment.to_string()
}
