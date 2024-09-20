use crate::helpers::try_parse_url_path::try_parse_url_path;
use crate::route_builder::replace_segment_with_param::replace_segment_with_param;

pub fn build_route_from_url_str(url: &str) -> Option<String> {
    let path = try_parse_url_path(url)?;

    let route: String = path
        .split('/')
        .map(replace_segment_with_param)
        .collect::<Vec<String>>()
        .join("/");

    if route == "/" {
        return Some("/".to_string());
    }

    if route.ends_with('/') {
        return Some(route[..route.len() - 1].to_string());
    }

    Some(route)
}
