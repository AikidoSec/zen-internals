mod ai;
mod output;
mod proxy;

use std::process::ExitCode;

use rama::{
    error::{BoxError, ErrorContext as _},
    net::address::ProxyAddress,
    telemetry::tracing::{self, level_filters::LevelFilter},
    tls::boring::core::{rand::rand_bytes, x509::X509},
};

const USERNAME: &str = "zen";

const USAGE: &str =
    "usage: zen-proxy [--upstream-proxy <http://host:port>] [--upstream-ca <pem file>]";

pub struct Args {
    pub upstream_proxy: Option<ProxyAddress>,
    pub upstream_ca: Vec<X509>,
}

fn parse_args() -> Result<Args, BoxError> {
    let mut args = Args {
        upstream_proxy: None,
        upstream_ca: Vec::new(),
    };
    let mut argv = std::env::args().skip(1);
    while let Some(flag) = argv.next() {
        let mut value = || {
            argv.next()
                .ok_or_else(|| format!("{flag} requires a value"))
        };
        match flag.as_str() {
            "--upstream-proxy" => {
                args.upstream_proxy = Some(
                    ProxyAddress::try_from(value()?.as_str()).context("parse --upstream-proxy")?,
                )
            }
            "--upstream-ca" => {
                let pem = std::fs::read(value()?).context("read --upstream-ca")?;
                args.upstream_ca = X509::stack_from_pem(&pem).context("parse --upstream-ca")?;
            }
            _ => return Err(format!("unknown argument: {flag}").into()),
        }
    }
    Ok(args)
}

fn random_password() -> Result<String, BoxError> {
    let mut bytes = [0u8; 24];
    rand_bytes(&mut bytes).context("generate proxy password")?;
    Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
}

fn exit_when_stdin_closes() {
    std::thread::spawn(|| {
        let _ = std::io::copy(&mut std::io::stdin().lock(), &mut std::io::sink());
        std::process::exit(0);
    });
}

/// The parent app owns shutdown: process-group signals (Ctrl+C, systemd, PM2, dumb-init) must not
/// cut its in-flight LLM calls. Tokio keeps the handlers registered for the process lifetime.
fn ignore_shutdown_signals() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let _ = signal(SignalKind::interrupt());
        let _ = signal(SignalKind::terminate());
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    ignore_shutdown_signals();
    tracing::subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_max_level(LevelFilter::WARN)
        .with_ansi(false)
        .init();

    let args = match parse_args() {
        Ok(args) => args,
        Err(err) => {
            eprintln!("{err}\n{USAGE}");
            return ExitCode::from(2);
        }
    };
    exit_when_stdin_closes();

    match run(args).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            tracing::error!("zen-proxy failed: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), BoxError> {
    let password = random_password()?;
    let hosts: Vec<&str> = ai::wire::hosts().collect();
    proxy::run(args, USERNAME, &password, |port, ca_pem| {
        output::send(&output::Line::Ready {
            port,
            username: USERNAME,
            password: &password,
            ca: ca_pem,
            hosts: &hosts,
        });
    })
    .await
}
