use anyhow::{Context, Result};
use axum::{Router, body::Body, extract::{Request, State}, http::StatusCode, response::Response};
use clap::Parser;
use gitgate::{audit, github, policy};
use hyper::service::service_fn;
use hyper_util::{rt::{TokioExecutor, TokioIo}, server::conn::auto::Builder as ServerBuilder};
use reqwest::Client;
use rustls::ServerConfig;
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tower::ServiceExt;

const HOP_BY_HOP: &[&str] = &[
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
];

#[derive(Parser)]
#[command(name = "gitgate-proxy", about = "GitGate policy-enforcing git proxy")]
struct Args {
    /// Port to listen on
    #[arg(long, default_value = "7474")]
    port: u16,
    /// Address to bind (0.0.0.0 to accept from the network)
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,
    /// Path to policy YAML file
    #[arg(long, short)]
    policy: Option<String>,
    /// Path to TLS certificate PEM file (enables HTTPS when paired with --tls-key)
    #[arg(long)]
    tls_cert: Option<String>,
    /// Path to TLS private key PEM file (enables HTTPS when paired with --tls-cert)
    #[arg(long)]
    tls_key: Option<String>,
}

struct AppState {
    client: Client,
    config: Arc<policy::Config>,
    token: Option<String>,
    cache: RwLock<HashMap<String, CacheEntry>>,
}

struct CacheEntry {
    action: policy::Action,
    reason: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    match (&args.tls_cert, &args.tls_key) {
        (Some(_), None) | (None, Some(_)) => {
            anyhow::bail!("--tls-cert and --tls-key must be provided together");
        }
        _ => {}
    }

    let config = policy::Config::load(args.policy.as_deref())?;
    let token = std::env::var("GITGATE_GITHUB_TOKEN").ok().filter(|t| !t.is_empty());

    let state = Arc::new(AppState {
        client: Client::builder().user_agent("gitgate-proxy/0.1").build()?,
        config: Arc::new(config),
        token,
        cache: RwLock::new(HashMap::new()),
    });

    let app = Router::new()
        .fallback(handle)
        .with_state(state);

    let addr: SocketAddr = format!("{}:{}", args.bind, args.port).parse()?;
    let tcp = TcpListener::bind(addr).await?;

    if let (Some(cert), Some(key)) = (args.tls_cert, args.tls_key) {
        let acceptor = make_tls_acceptor(&cert, &key)?;
        eprintln!("[gitgate] proxy listening on https://{}", addr);
        eprintln!("[gitgate] configure git:  git config --global url.\"https://{}/\".insteadOf \"https://github.com/\"", addr);
        serve_tls(app, tcp, acceptor).await?;
    } else {
        eprintln!("[gitgate] proxy listening on http://{}", addr);
        eprintln!("[gitgate] configure git:  git config --global url.\"http://{}/\".insteadOf \"https://github.com/\"", addr);
        axum::serve(tcp, app).await?;
    }

    Ok(())
}

// For TLS we can't use axum::serve directly (it has no built-in TLS acceptor),
// so we drive the hyper connection builder ourselves after the TLS handshake.
async fn serve_tls(app: Router, tcp: TcpListener, acceptor: TlsAcceptor) -> Result<()> {
    loop {
        match tcp.accept().await {
            Ok((stream, peer_addr)) => {
                let acceptor = acceptor.clone();
                let app = app.clone();
                tokio::spawn(async move {
                    handle_tls_conn(app, stream, peer_addr, acceptor).await;
                });
            }
            Err(e) => eprintln!("[proxy] TCP accept error: {e}"),
        }
    }
}

async fn handle_tls_conn(
    app: Router,
    stream: TcpStream,
    peer_addr: SocketAddr,
    acceptor: TlsAcceptor,
) {
    let tls_stream: TlsStream<TcpStream> = match acceptor.accept(stream).await {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[proxy] TLS handshake failed from {peer_addr}: {e}");
            return;
        }
    };

    let io = TokioIo::new(tls_stream);
    // Router implements Service<Request<B>> for any compatible B, including Incoming.
    let svc = service_fn(move |req| {
        let app = app.clone();
        async move { app.oneshot(req).await }
    });

    if let Err(e) = ServerBuilder::new(TokioExecutor::new())
        .serve_connection_with_upgrades(io, svc)
        .await
    {
        eprintln!("[proxy] connection error from {peer_addr}: {e}");
    }
}

fn make_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_data = std::fs::read(cert_path).context("reading TLS cert")?;
    let key_data = std::fs::read(key_path).context("reading TLS key")?;

    let certs: Vec<rustls::Certificate> =
        rustls_pemfile::certs(&mut cert_data.as_slice())
            .context("parsing TLS cert")?
            .into_iter()
            .map(rustls::Certificate)
            .collect();

    let key = rustls_pemfile::pkcs8_private_keys(&mut key_data.as_slice())
        .context("parsing TLS key")?
        .into_iter()
        .next()
        .map(rustls::PrivateKey)
        .ok_or_else(|| anyhow::anyhow!("no PKCS8 private key found in {}", key_path))?;

    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("TLS configuration error")?;

    Ok(TlsAcceptor::from(Arc::new(config)))
}

async fn handle(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let path = req.uri().path().to_owned();

    let (owner, repo_name) = match repo_from_path(&path) {
        Some(p) => p,
        None => return plain(StatusCode::BAD_REQUEST, "GitGate: cannot parse repo from path\n"),
    };

    let key = format!("{}/{}", owner, repo_name);

    {
        let cache = state.cache.read().await;
        if let Some(entry) = cache.get(&key) {
            return match entry.action {
                policy::Action::Allow => {
                    eprintln!("[gate] ALLOW (cached) {}", key);
                    forward(req, state.client.clone()).await
                }
                policy::Action::Block => {
                    eprintln!("[gate] BLOCK (cached) {} — {}", key, entry.reason);
                    block(&entry.reason)
                }
            };
        }
    }

    let meta = match github::fetch_repo_meta(&owner, &repo_name, state.token.as_deref()).await {
        Ok(m) => m,
        Err(e) => {
            eprintln!("[gate] GitHub API error for {}: {}", key, e);
            return plain(
                StatusCode::BAD_GATEWAY,
                &format!("GitGate: could not fetch repo metadata — {}\n", e),
            );
        }
    };

    let decision = policy::evaluate(&state.config, &meta);

    let audit_entry = audit::Entry::new(&key, &meta, &decision);
    if let Err(e) = audit_entry.write(&state.config.audit_log_path) {
        eprintln!("[gate] audit write error: {}", e);
    }

    let action = decision.action.clone();
    let reason = decision.reason.clone();

    state.cache.write().await.insert(key.clone(), CacheEntry {
        action: action.clone(),
        reason: reason.clone(),
    });

    match action {
        policy::Action::Allow => {
            eprintln!("[gate] ALLOW {} — {}", key, reason);
            forward(req, state.client.clone()).await
        }
        policy::Action::Block => {
            eprintln!("[gate] BLOCK {} — {}", key, reason);
            block(&reason)
        }
    }
}

async fn forward(req: Request, client: Client) -> Response {
    let method = req.method().clone();
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_owned();
    let req_headers = req.headers().clone();

    let body_bytes = match axum::body::to_bytes(req.into_body(), 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[proxy] body read error: {e}");
            return plain(StatusCode::BAD_REQUEST, "could not read request body\n");
        }
    };

    let target = format!("https://github.com{}", path_and_query);
    let mut fwd = client.request(method.clone(), &target);
    for (name, value) in &req_headers {
        if !HOP_BY_HOP.contains(&name.as_str()) && name.as_str() != "host" {
            fwd = fwd.header(name, value);
        }
    }
    fwd = fwd.body(body_bytes);

    match fwd.send().await {
        Ok(upstream) => {
            let status = upstream.status();
            let resp_headers = upstream.headers().clone();
            eprintln!("[proxy] {} {} → {}", method, path_and_query, status);

            let mut builder = Response::builder().status(status);
            for (name, value) in &resp_headers {
                if !HOP_BY_HOP.contains(&name.as_str()) {
                    builder = builder.header(name, value);
                }
            }
            builder
                .body(Body::from_stream(upstream.bytes_stream()))
                .unwrap_or_else(|e| plain(StatusCode::INTERNAL_SERVER_ERROR, &e.to_string()))
        }
        Err(e) => {
            eprintln!("[proxy] upstream error for {}: {}", path_and_query, e);
            plain(StatusCode::BAD_GATEWAY, &format!("GitGate: upstream error — {}\n", e))
        }
    }
}

fn block(reason: &str) -> Response {
    plain(
        StatusCode::FORBIDDEN,
        &format!(
            "GitGate: clone blocked\nReason: {}\n\nContact your security team to request an exception.\n",
            reason
        ),
    )
}

fn plain(status: StatusCode, msg: &str) -> Response {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .body(Body::from(msg.to_owned()))
        .unwrap()
}

/// Extracts (owner, repo) from a git smart-HTTP path.
/// Handles both `/owner/repo/...` and `/owner/repo.git/...`.
fn repo_from_path(path: &str) -> Option<(String, String)> {
    let segs: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
    if segs.len() < 2 {
        return None;
    }
    let owner = segs[0].to_owned();
    let repo = segs[1].trim_end_matches(".git").to_owned();
    if owner.is_empty() || repo.is_empty() {
        return None;
    }
    Some((owner, repo))
}

#[cfg(test)]
mod tests {
    use super::repo_from_path;

    #[test]
    fn parses_git_paths() {
        assert_eq!(repo_from_path("/octocat/Hello-World/info/refs"), Some(("octocat".into(), "Hello-World".into())));
        assert_eq!(repo_from_path("/octocat/Hello-World.git/info/refs"), Some(("octocat".into(), "Hello-World".into())));
        assert_eq!(repo_from_path("/octocat/Hello-World/git-upload-pack"), Some(("octocat".into(), "Hello-World".into())));
        assert_eq!(repo_from_path("/"), None);
        assert_eq!(repo_from_path("/onlyone"), None);
    }
}
