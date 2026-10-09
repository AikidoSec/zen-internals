use std::{convert::Infallible, sync::Arc, time::Duration};

use rama::{
    Layer, Service as _,
    crypto::{cert::boring::generate_certificate_authority_x509, pki_types::CertificateDer},
    dns::client::DnsConnector,
    error::{BoxError, ErrorContext as _},
    extensions::Extensions,
    http::{
        Method, Request, Response, StatusCode,
        client::proxy::layer::HttpProxyConnectorLayer,
        layer::{
            proxy_auth::ProxyAuthLayer, upgrade::EagerHttpProxyConnector, upgrade::UpgradeLayer,
        },
        service::web::response::IntoResponse as _,
    },
    layer::{ArcLayer, ConsumeErrLayer, TimeoutLayer},
    matcher::Matcher,
    net::{
        AuthorityInputExt as _, client::ProxyAddressLayer, socket::SocketOptions,
        user::credentials::Basic,
    },
    rt::Executor,
    service::service_fn,
    tcp::{client::service::TcpConnector, server::TcpListener},
    tls::{
        boring::proxy::{TlsMitmEgressServerAuth, TlsMitmRelay},
        client::ServerVerifyMode,
        server::{CertificateSubject, PeekTlsClientHelloService, SelfSignedCaConfig},
    },
};

use rama_http_backend::{
    proxy::mitm::{DefaultErrorResponse, HttpMitmRelay},
    server::HttpServer,
};

use crate::{
    Args,
    ai::{self, wire::Provider},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Binds the CONNECT proxy on a random loopback port, calls `on_ready(port, ca_pem)`
/// and serves until the process exits.
pub async fn run(
    args: Args,
    username: &str,
    password: &str,
    on_ready: impl FnOnce(u16, &str),
) -> Result<(), BoxError> {
    let exec = Executor::default();

    let (ca_crt, ca_key) = generate_certificate_authority_x509(&SelfSignedCaConfig {
        subject: CertificateSubject {
            organisation_name: Some("Aikido Security".to_owned()),
            common_name: Some("Zen proxy CA".to_owned()),
        },
        ..Default::default()
    })
    .context("generate CA")?;
    let ca_pem = String::from_utf8(ca_crt.to_pem().context("encode CA")?)?;

    let mut server_auth = TlsMitmEgressServerAuth::new().with_server_verify(ServerVerifyMode::Auto);
    if !args.upstream_ca.is_empty() {
        let anchors = args
            .upstream_ca
            .iter()
            .map(|crt| crt.to_der().map(CertificateDer::from))
            .collect::<Result<Vec<_>, _>>()
            .context("encode --upstream-ca")?;
        server_auth = server_auth.try_with_extra_server_trust_anchors(anchors)?;
    }
    let tls_relay =
        TlsMitmRelay::new_cached_in_memory(ca_crt, ca_key).with_egress_server_auth(server_auth);

    let http_relay = HttpMitmRelay::new(exec.clone()).with_http_middleware((
        ConsumeErrLayer::trace_as_debug().with_response(DefaultErrorResponse::new()),
        ai::InspectLayer,
        ArcLayer::new(),
    ));
    let mitm = Arc::new(ConsumeErrLayer::trace_as_warning().into_layer(
        PeekTlsClientHelloService::new(tls_relay.into_layer(http_relay)),
    ));

    let connector = TimeoutLayer::new(CONNECT_TIMEOUT).into_layer(
        HttpProxyConnectorLayer::optional()
            .with_tls_proxy_support(false)
            .into_layer(DnsConnector::new(TcpConnector::new().with_connector(
                Arc::new(SocketOptions {
                    tcp_no_delay: Some(true),
                    ..SocketOptions::default_tcp()
                }),
            ))),
    );

    let proxy_service = (
        ConsumeErrLayer::default(),
        ProxyAuthLayer::new(Basic::new(username.try_into()?, password.try_into()?)),
        ProxyAddressLayer::maybe(args.upstream_proxy),
        UpgradeLayer::new(
            exec.clone(),
            AllowedConnect,
            EagerHttpProxyConnector::new(connector, mitm),
        ),
    )
        .into_layer(service_fn(forbidden));
    let http_server = HttpServer::auto(exec.clone()).service(Arc::new(proxy_service));

    let listener = TcpListener::build(exec)
        .bind_address("127.0.0.1:0")
        .await
        .context("bind proxy")?;
    let port = listener.local_addr().context("proxy address")?.port();
    on_ready(port, &ca_pem);
    // Without TCP_NODELAY, Nagle + delayed ACK add ~40 ms to every proxied request.
    listener
        .serve(service_fn(move |stream: rama::tcp::TcpStream| {
            let http_server = http_server.clone();
            async move {
                let _ = stream.stream.set_nodelay(true);
                http_server.serve(stream).await
            }
        }))
        .await;
    Ok(())
}

/// Only CONNECT to port 443 of a known host is tunnelled; this is not an open proxy.
struct AllowedConnect;

impl Matcher<Request> for AllowedConnect {
    fn matches(&self, _ext: Option<&Extensions>, req: &Request) -> bool {
        req.method() == Method::CONNECT
            && req.authority().is_some_and(|authority| {
                authority.port.as_u16() == Some(443)
                    && Provider::from_host(&authority.host.to_string()).is_some()
            })
    }
}

async fn forbidden(_req: Request) -> Result<Response, Infallible> {
    Ok(StatusCode::FORBIDDEN.into_response())
}
