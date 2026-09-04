use wirefilter::{Scheme, SchemeBuilder, Type};

pub fn build_http_scheme() -> Scheme {
    let mut scheme = SchemeBuilder::new();

    scheme.add_field("http.host", Type::Bytes).unwrap();
    scheme
        .add_field("http.request.method", Type::Bytes)
        .unwrap();
    scheme.add_field("http.request.uri", Type::Bytes).unwrap();
    scheme
        .add_field("http.request.uri.path", Type::Bytes)
        .unwrap();
    scheme
        .add_field("http.request.uri.query", Type::Bytes)
        .unwrap();
    scheme
        .add_field("http.request.full_uri", Type::Bytes)
        .unwrap();
    scheme.add_field("http.user_agent", Type::Bytes).unwrap();
    scheme.add_field("http.cookie", Type::Bytes).unwrap();
    scheme.add_field("http.referer", Type::Bytes).unwrap();
    scheme
        .add_field("http.x_forwarded_for", Type::Bytes)
        .unwrap();
    scheme
        .add_field("http.request.body.raw", Type::Bytes)
        .unwrap();
    scheme.add_optional_field("ip.src", Type::Ip).unwrap();

    scheme.build()
}
