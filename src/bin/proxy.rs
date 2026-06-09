use anyhow::{Context, Result};
use axum::{Router, body::Body, extract::{Request, State}, http::StatusCode, response::Response};
use clap::Parser;
use gitgate::{audit, github, policy};
use hyper::service::service_fn;
use hyper_util::{rt::{TokioExecutor, TokioIo}, server::conn::auto::Builder as ServerBuilder};
use reqwest::Client;
use rustls::ServerConfig;
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::{Duration, Instant}};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::RwLock;
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tower::ServiceExt;

const HOP_BY_HOP: &[&str] = &[
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade",
];
const CACHE_TTL: Duration = Duration::from_secs(3600);

#[derive(Parser)]
#[command(name = "gitgate-proxy", about = "GitGate policy-enforcing git proxy")]
struct Args {
    #[arg(long, default_value = "7474")]
    port: u16,
    #[arg(long, default_value = "0.0.0.0")]
    bind: String,
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
    reasons: Vec<String>,
    license: Option<String>,
    repo_age_days: i64,
    stars: u64,
    inserted_at: Instant,
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
        // Only follow redirects that stay on github.com to prevent SSRF via
        // redirect chaining to internal hosts.
        client: Client::builder()
            .user_agent("gitgate-proxy/0.1")
            .redirect(reqwest::redirect::Policy::custom(|attempt| {
                if attempt.url().host_str() == Some("github.com") {
                    attempt.follow()
                } else {
                    attempt.stop()
                }
            }))
            .build()?,
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
        eprintln!("[gitgate] WARNING: running in plain HTTP mode — policy enforcement can be");
        eprintln!("[gitgate] bypassed by any on-path attacker. Use --tls-cert/--tls-key for production.");
        eprintln!("[gitgate] proxy listening on http://{}", addr);
        eprintln!("[gitgate] configure git:  git config --global url.\"http://{}/\".insteadOf \"https://github.com/\"", addr);
        axum::serve(tcp, app).await?;
    }

    Ok(())
}

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

    // Normalize key for cache lookup.
    let key = format!("{}/{}", owner, repo_name).to_lowercase();

    // Check cache — skip if entry is expired.
    {
        let cache = state.cache.read().await;
        if let Some(entry) = cache.get(&key) {
            if entry.inserted_at.elapsed() < CACHE_TTL {
                let action = entry.action.clone();
                let reason = entry.reason.clone();
                let audit = audit::Entry {
                    id: format!("gg-{}", uuid::Uuid::new_v4()),
                    timestamp: chrono::Utc::now().to_rfc3339(),
                    action: action.clone(),
                    repo: key.clone(),
                    license: entry.license.clone(),
                    repo_age_days: entry.repo_age_days,
                    stars: entry.stars,
                    reasons: entry.reasons.clone(),
                    gitgate_version: env!("CARGO_PKG_VERSION"),
                };
                drop(cache);
                if let Err(e) = audit.write(&state.config.audit_log_path) {
                    eprintln!("[gate] audit write error: {}", e);
                }
                return match action {
                    policy::Action::Allow => {
                        eprintln!("[gate] ALLOW (cached) {}", key);
                        forward(req, state.client.clone(), &owner, &repo_name).await
                    }
                    policy::Action::Block => {
                        eprintln!("[gate] BLOCK (cached) {} — {}", key, reason);
                        block(&reason)
                    }
                };
            }
            // Entry expired — fall through to re-check.
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

    // Use the API-canonical full_name as the cache key so renamed/transferred
    // repos are keyed consistently rather than by whatever the client typed.
    let canonical_key = meta.full_name.to_lowercase();
    state.cache.write().await.insert(canonical_key, CacheEntry {
        action: action.clone(),
        reason: reason.clone(),
        reasons: decision.reasons.clone(),
        license: meta.license_id().map(|s| s.to_string()),
        repo_age_days: meta.age_days(),
        stars: meta.stargazers_count,
        inserted_at: Instant::now(),
    });

    match action {
        policy::Action::Allow => {
            eprintln!("[gate] ALLOW {} — {}", key, reason);
            forward(req, state.client.clone(), &owner, &repo_name).await
        }
        policy::Action::Block => {
            eprintln!("[gate] BLOCK {} — {}", key, reason);
            block(&reason)
        }
    }
}

async fn forward(req: Request, client: Client, owner: &str, repo_name: &str) -> Response {
    let method = req.method().clone();
    let req_headers = req.headers().clone();

    // Reconstruct the upstream URL from the validated owner/repo rather than
    // forwarding the raw client-supplied path, preventing path traversal bypass.
    let suffix = path_suffix(req.uri().path(), owner, repo_name);
    let query = req.uri().query()
        .map(|q| format!("?{}", q))
        .unwrap_or_default();
    let target = format!("https://github.com/{}/{}{}{}", owner, repo_name, suffix, query);

    let body_bytes = match axum::body::to_bytes(req.into_body(), 8 * 1024 * 1024).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("[proxy] body read error: {e}");
            return plain(StatusCode::BAD_REQUEST, "could not read request body\n");
        }
    };

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
            eprintln!("[proxy] {} {} → {}", method, target, status);

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
            eprintln!("[proxy] upstream error for {}: {}", target, e);
            plain(StatusCode::BAD_GATEWAY, &format!("GitGate: upstream error — {}\n", e))
        }
    }
}

/// Extracts the path suffix after /owner/repo[.git], used to reconstruct
/// the upstream URL from validated components.
fn path_suffix<'a>(path: &'a str, owner: &str, repo: &str) -> &'a str {
    let with_git = format!("/{}/{}.git", owner, repo);
    let without_git = format!("/{}/{}", owner, repo);
    if let Some(s) = path.strip_prefix(&with_git) {
        s
    } else if let Some(s) = path.strip_prefix(&without_git) {
        s
    } else {
        ""
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
    use super::{repo_from_path, path_suffix};

    #[test]
    fn parses_git_paths() {
        assert_eq!(repo_from_path("/octocat/Hello-World/info/refs"), Some(("octocat".into(), "Hello-World".into())));
        assert_eq!(repo_from_path("/octocat/Hello-World.git/info/refs"), Some(("octocat".into(), "Hello-World".into())));
        assert_eq!(repo_from_path("/octocat/Hello-World/git-upload-pack"), Some(("octocat".into(), "Hello-World".into())));
        assert_eq!(repo_from_path("/"), None);
        assert_eq!(repo_from_path("/onlyone"), None);
    }

    #[test]
    fn extracts_path_suffix() {
        assert_eq!(path_suffix("/octocat/Hello-World/info/refs", "octocat", "Hello-World"), "/info/refs");
        assert_eq!(path_suffix("/octocat/Hello-World.git/info/refs", "octocat", "Hello-World"), "/info/refs");
        assert_eq!(path_suffix("/octocat/Hello-World/git-upload-pack", "octocat", "Hello-World"), "/git-upload-pack");
    }
}
