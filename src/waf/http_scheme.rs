use wirefilter::{Scheme, Type};

pub fn build_http_scheme() -> Scheme {
    let mut scheme = Scheme::new();

    // Standard fields (matching Cloudflare field naming)
    // https://developers.cloudflare.com/ruleset-engine/rules-language/fields/reference/
    scheme.add_field("http.host".into(), Type::Bytes).unwrap();
    scheme
        .add_field("http.request.method".into(), Type::Bytes)
        .unwrap();
    scheme
        .add_field("http.request.uri".into(), Type::Bytes)
        .unwrap();
    scheme
        .add_field("http.request.uri.path".into(), Type::Bytes)
        .unwrap();
    scheme
        .add_field("http.request.uri.query".into(), Type::Bytes)
        .unwrap();
    scheme
        .add_field("http.request.full_uri".into(), Type::Bytes)
        .unwrap();
    scheme
        .add_field("http.user_agent".into(), Type::Bytes)
        .unwrap();
    scheme.add_field("http.cookie".into(), Type::Bytes).unwrap();
    scheme
        .add_field("http.referer".into(), Type::Bytes)
        .unwrap();
    scheme
        .add_field("http.x_forwarded_for".into(), Type::Bytes)
        .unwrap();
    scheme
        .add_field("http.request.body.raw".into(), Type::Bytes)
        .unwrap();
    scheme.add_field("ip.src".into(), Type::Ip).unwrap();

    scheme
}
