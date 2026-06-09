use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use std::{net::IpAddr, path::Path};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

#[derive(Parser)]
#[command(name = "gitgate-cert", about = "Generate TLS certificates for GitGate proxy")]
struct Args {
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate CA and server certificate
    Generate {
        /// Output directory for generated certificate files
        #[arg(long, default_value = ".")]
        out_dir: String,
        /// Hostname for the server certificate SAN (repeat for multiple)
        #[arg(long, default_value = "localhost")]
        hostname: Vec<String>,
    },
}

fn main() -> Result<()> {
    match Args::parse().command {
        Cmd::Generate { out_dir, hostname } => generate(&out_dir, &hostname),
    }
}

fn generate(out_dir: &str, hostnames: &[String]) -> Result<()> {
    let out = Path::new(out_dir);
    std::fs::create_dir_all(out).context("creating output directory")?;

    // CA key + self-signed certificate
    let ca_key = KeyPair::generate()?;
    let mut ca_params = CertificateParams::default();
    // Constrained(0): CA can sign leaf certs but cannot delegate to sub-CAs.
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca_params.distinguished_name.push(DnType::CommonName, "GitGate CA");
    ca_params.distinguished_name.push(DnType::OrganizationName, "GitGate");
    let ca_cert = ca_params.self_signed(&ca_key)?;

    // Server key + certificate signed by the CA
    let server_key = KeyPair::generate()?;
    let mut server_params = CertificateParams::new(hostnames.to_vec())?;
    server_params.distinguished_name.push(DnType::CommonName, "gitgate-proxy");
    // Always include the loopback IP so local testing works without extra steps
    server_params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)));
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    let ca_path = out.join("ca.crt");
    let cert_path = out.join("server.crt");
    let key_path = out.join("server.key");

    std::fs::write(&ca_path, ca_cert.pem()).context("writing ca.crt")?;
    std::fs::write(&cert_path, server_cert.pem()).context("writing server.crt")?;
    std::fs::write(&key_path, server_key.serialize_pem()).context("writing server.key")?;
    // Private key must not be world-readable.
    #[cfg(unix)]
    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o600))
        .context("setting server.key permissions to 0600")?;

    println!("[gitgate-cert] Generated in {out_dir}/");
    println!("  ca.crt     — install on developer machines");
    println!(
        "  server.crt — proxy certificate  (SANs: {}, 127.0.0.1)",
        hostnames.join(", ")
    );
    println!("  server.key — proxy private key");
    println!();
    println!("Install the CA on developer machines:");
    println!(
        "  macOS:   sudo security add-trusted-cert -d -r trustRoot \\\n             -k /Library/Keychains/System.keychain {}",
        ca_path.display()
    );
    println!(
        "  Linux:   sudo cp {} /usr/local/share/ca-certificates/gitgate.crt \\\n             && sudo update-ca-certificates",
        ca_path.display()
    );
    println!(
        "  Windows: certutil -addstore -f \"ROOT\" {}",
        ca_path.display()
    );
    println!();
    println!("Run the proxy with TLS:");
    println!(
        "  gitgate-proxy --port 7443 --tls-cert {} --tls-key {}",
        cert_path.display(),
        key_path.display()
    );
    println!();
    let first_host = hostnames.first().map(String::as_str).unwrap_or("localhost");
    println!("Configure git on developer machines:");
    println!(
        "  git config --global url.\"https://{first_host}:7443/\".insteadOf \"https://github.com/\""
    );

    Ok(())
}
