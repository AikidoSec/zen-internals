use std::{io::Write as _, path::PathBuf, process::Stdio, time::Duration};

use rama::{
    crypto::cert::{CertificateIdentity, GeneratedServerAuthConfig, generate_server_auth},
    net::address::Domain,
    tls::boring::core::{
        pkey::PKey,
        ssl::{SslAcceptor, SslConnector, SslMethod, SslVerifyMode},
        tokio as boring_tokio,
        x509::X509,
    },
};
use serde_json::Value;
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWriteExt, BufReader},
    net::{TcpListener, TcpStream},
    process::{Child, ChildStdout, Command},
    time::timeout,
};

const TIMEOUT: Duration = Duration::from_secs(10);

const CHAT_RESPONSE: &str = r#"{"id":"x","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","tool_calls":[{"id":"c1","type":"function","function":{"name":"get_weather","arguments":"{}"}}]}}],"usage":{"prompt_tokens":10,"completion_tokens":5,"prompt_tokens_details":{"cached_tokens":2}}}"#;

/// Fake egress proxy: accepts any CONNECT and terminates TLS itself with a certificate for
/// api.openai.com issued by its own CA, answering every request with a gzipped chat completion.
async fn start_fake_upstream() -> (u16, PathBuf, Vec<u8>) {
    let (chain, key) = generate_server_auth(GeneratedServerAuthConfig::generated_ca_for(
        CertificateIdentity::Dns(Domain::from_static("api.openai.com")),
    ))
    .unwrap();
    let leaf = X509::from_der(chain[0].as_ref()).unwrap();
    let ca = X509::from_der(chain.last().unwrap().as_ref()).unwrap();
    let key = PKey::private_key_from_der(key.secret_der()).unwrap();

    let mut acceptor = SslAcceptor::mozilla_intermediate_v5(SslMethod::tls_server()).unwrap();
    acceptor.set_certificate(&leaf).unwrap();
    acceptor.add_extra_chain_cert(ca.clone()).unwrap();
    acceptor.set_private_key(&key).unwrap();
    let acceptor = acceptor.build();

    let mut gzipped = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzipped.write_all(CHAT_RESPONSE.as_bytes()).unwrap();
    let gzipped = gzipped.finish().unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let ca_path = std::env::temp_dir().join(format!("zen-proxy-test-ca-{port}.pem"));
    std::fs::write(&ca_path, ca.to_pem().unwrap()).unwrap();
    let body = gzipped.clone();
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let body = body.clone();
            tokio::spawn(async move {
                read_head(&mut stream).await;
                stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.unwrap();
                let Ok(mut tls) = boring_tokio::accept(&acceptor, stream).await else {
                    return;
                };
                let head = read_head(&mut tls).await;
                let length = header(&head, "content-length").map_or(0, |v| v.parse().unwrap());
                let mut request_body = vec![0; length];
                tls.read_exact(&mut request_body).await.unwrap();
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-encoding: gzip\r\ncontent-length: {}\r\nconnection: close\r\n\r\n",
                    body.len()
                );
                tls.write_all(response.as_bytes()).await.unwrap();
                tls.write_all(&body).await.unwrap();
                let _ = tls.shutdown().await;
            });
        }
    });
    (port, ca_path, gzipped)
}

async fn read_head(stream: &mut (impl AsyncRead + Unpin)) -> String {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let byte = stream.read_u8().await.unwrap();
        head.push(byte);
    }
    String::from_utf8(head).unwrap()
}

fn header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

struct Proxy {
    child: Child,
    stdout: tokio::io::Lines<BufReader<ChildStdout>>,
    port: u16,
    password: String,
    ca: X509,
}

async fn start_proxy(args: &[&str]) -> Proxy {
    let mut child = Command::new(env!("CARGO_BIN_EXE_zen-proxy"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap()).lines();
    let ready: Value = serde_json::from_str(&next_line(&mut stdout).await.unwrap()).unwrap();
    assert_eq!(ready["type"], "ready");
    assert_eq!(ready["username"], "zen");
    let hosts = ready["hosts"].as_array().unwrap();
    assert!(hosts.contains(&Value::from("api.openai.com")));
    assert!(hosts.contains(&Value::from("bedrock-runtime.*.amazonaws.com")));
    Proxy {
        child,
        stdout,
        port: ready["port"].as_u64().unwrap() as u16,
        password: ready["password"].as_str().unwrap().to_owned(),
        ca: X509::from_pem(ready["ca"].as_str().unwrap().as_bytes()).unwrap(),
    }
}

async fn next_line(stdout: &mut tokio::io::Lines<BufReader<ChildStdout>>) -> Option<String> {
    timeout(TIMEOUT, stdout.next_line()).await.ok()?.unwrap()
}

fn basic_auth(password: &str) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.encode(format!("zen:{password}"))
}

async fn connect(proxy: &Proxy, target: &str, password: Option<&str>) -> (String, TcpStream) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    let auth = password
        .map(|password| format!("Proxy-Authorization: Basic {}\r\n", basic_auth(password)))
        .unwrap_or_default();
    let request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n{auth}\r\n");
    stream.write_all(request.as_bytes()).await.unwrap();
    let head = timeout(TIMEOUT, read_head(&mut stream)).await.unwrap();
    (head.lines().next().unwrap().to_owned(), stream)
}

async fn post_chat_completion(
    proxy: &Proxy,
    host: &str,
    stream: TcpStream,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut connector = SslConnector::builder(SslMethod::tls_client())?;
    connector.cert_store_mut().add_cert(proxy.ca.clone())?;
    connector.set_verify(SslVerifyMode::PEER);
    let config = connector.build().configure()?;
    let mut tls = boring_tokio::connect(config, Some(host), stream).await?;

    let body = r#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}"#;
    let request = format!(
        "POST /v1/chat/completions HTTP/1.1\r\nHost: {host}\r\ncontent-type: application/json\r\naccept-encoding: gzip\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    tls.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    timeout(TIMEOUT, tls.read_to_end(&mut response)).await??;
    Ok(response)
}

fn split_response(response: &[u8]) -> (String, &[u8]) {
    let end = response.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
    (
        String::from_utf8_lossy(&response[..end]).into_owned(),
        &response[end..],
    )
}

#[tokio::test]
async fn proxy_reports_ai_calls_and_enforces_access() {
    let (upstream_port, upstream_ca, gzipped_body) = start_fake_upstream().await;
    let upstream_proxy = format!("http://127.0.0.1:{upstream_port}");
    let mut proxy = start_proxy(&[
        "--upstream-proxy",
        &upstream_proxy,
        "--upstream-ca",
        upstream_ca.to_str().unwrap(),
    ])
    .await;
    std::fs::remove_file(upstream_ca).unwrap();

    let (status, stream) = connect(&proxy, "api.openai.com:443", Some(&proxy.password)).await;
    assert!(status.contains(" 200"), "{status}");
    let response = post_chat_completion(&proxy, "api.openai.com", stream)
        .await
        .unwrap();
    let (head, body) = split_response(&response);
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    assert_eq!(header(&head, "content-encoding"), Some("gzip"));
    assert_eq!(
        body,
        gzipped_body.as_slice(),
        "client receives the upstream bytes unchanged"
    );

    let line: Value = serde_json::from_str(&next_line(&mut proxy.stdout).await.unwrap()).unwrap();
    assert_eq!(
        line,
        serde_json::json!({
            "type": "ai_call",
            "provider": "openai",
            "model": "gpt-4o-mini",
            "input_tokens": 10,
            "output_tokens": 5,
            "cache_read_tokens": 2,
            "cache_write_tokens": 0,
            "tools_called": ["get_weather"],
        })
    );

    let (status, _) = connect(&proxy, "api.openai.com:443", None).await;
    assert!(status.contains(" 407"), "{status}");
    let (status, _) = connect(&proxy, "api.openai.com:443", Some("wrong")).await;
    assert!(status.contains(" 407"), "{status}");
    let (status, _) = connect(&proxy, "example.com:443", Some(&proxy.password)).await;
    assert!(status.contains(" 403"), "{status}");
    let (status, _) = connect(&proxy, "api.openai.com:80", Some(&proxy.password)).await;
    assert!(status.contains(" 403"), "{status}");

    #[cfg(unix)]
    {
        let pid = proxy.child.id().unwrap().to_string();
        for signal in ["-INT", "-TERM"] {
            let status = std::process::Command::new("kill")
                .args([signal, &pid])
                .status()
                .unwrap();
            assert!(status.success());
        }
        let (status, _) = connect(&proxy, "example.com:443", Some(&proxy.password)).await;
        assert!(
            status.contains(" 403"),
            "proxy survives SIGINT/SIGTERM: {status}"
        );
    }

    drop(proxy.child.stdin.take());
    let exit = timeout(TIMEOUT, proxy.child.wait()).await.unwrap().unwrap();
    assert!(exit.success(), "proxy exits when stdin closes");
}

#[tokio::test]
async fn proxy_rejects_untrusted_upstream_certificate() {
    let (upstream_port, upstream_ca, _) = start_fake_upstream().await;
    std::fs::remove_file(upstream_ca).unwrap();
    let upstream_proxy = format!("http://127.0.0.1:{upstream_port}");

    let mut proxy = start_proxy(&["--upstream-proxy", &upstream_proxy]).await;

    let (status, stream) = connect(&proxy, "api.openai.com:443", Some(&proxy.password)).await;
    assert!(status.contains(" 200"), "{status}");
    let result = post_chat_completion(&proxy, "api.openai.com", stream).await;
    assert!(result.is_err(), "TLS to the client must fail: {result:?}");
    assert!(
        timeout(Duration::from_millis(500), proxy.stdout.next_line())
            .await
            .is_err(),
        "no ai_call for a rejected upstream"
    );
}

#[tokio::test]
async fn proxy_rejects_upstream_certificate_for_other_host() {
    let (upstream_port, upstream_ca, _) = start_fake_upstream().await;
    let upstream_proxy = format!("http://127.0.0.1:{upstream_port}");
    let mut proxy = start_proxy(&[
        "--upstream-proxy",
        &upstream_proxy,
        "--upstream-ca",
        upstream_ca.to_str().unwrap(),
    ])
    .await;
    std::fs::remove_file(upstream_ca).unwrap();

    // The fake upstream's trusted certificate only covers api.openai.com.
    let (status, stream) = connect(&proxy, "api.anthropic.com:443", Some(&proxy.password)).await;
    assert!(status.contains(" 200"), "{status}");
    let result = post_chat_completion(&proxy, "api.anthropic.com", stream).await;
    assert!(result.is_err(), "TLS to the client must fail: {result:?}");
    assert!(
        timeout(Duration::from_millis(500), proxy.stdout.next_line())
            .await
            .is_err(),
        "no ai_call for an upstream certificate with the wrong hostname"
    );
}
