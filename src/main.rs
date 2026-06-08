mod audit;
mod github;
mod policy;

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "gitgate", version, about = "Git proxy with open source policy enforcement")]
struct Cli {
    /// Path to policy YAML file (default: gitgate-policy.yaml in current directory)
    #[arg(long, short, global = true)]
    policy: Option<String>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Clone a repository after policy check
    Clone {
        /// Repository in owner/repo format
        repo: String,
        /// Extra arguments passed directly to git clone (e.g. --depth 1 my-dir)
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        git_args: Vec<String>,
    },
    /// Dry-run policy check without cloning
    Check {
        /// Repository in owner/repo format
        repo: String,
    },
    /// Policy inspection commands
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },
}

#[derive(Subcommand)]
enum PolicyCommands {
    /// Show the active policy and where it was loaded from
    Show,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Clone { repo, git_args } => {
            clone_command(&repo, &git_args, cli.policy.as_deref()).await?;
        }
        Commands::Check { repo } => {
            check_command(&repo, cli.policy.as_deref()).await?;
        }
        Commands::Policy { command: PolicyCommands::Show } => {
            policy_show_command(cli.policy.as_deref())?;
        }
    }

    Ok(())
}

async fn clone_command(repo: &str, git_args: &[String], policy_path: Option<&str>) -> Result<()> {
    let (owner, name) = parse_repo(repo)?;

    let config = policy::Config::load(policy_path)?;
    let token = std::env::var("GITGATE_GITHUB_TOKEN").ok().filter(|t| !t.is_empty());

    let meta = github::fetch_repo_meta(owner, name, token.as_deref()).await?;
    let decision = policy::evaluate(&config, &meta);

    let entry = audit::Entry::new(repo, &meta, &decision);
    entry.write(&config.audit_log_path)?;

    match decision.action {
        policy::Action::Allow => {
            println!("  GitGate: ALLOW — {}", decision.reason);
            let url = format!("https://github.com/{}", repo);
            let status = std::process::Command::new("git")
                .arg("clone")
                .arg(&url)
                .args(git_args)
                .status()?;
            std::process::exit(status.code().unwrap_or(1));
        }
        policy::Action::Block => {
            eprintln!("\n  GitGate Policy Block");
            eprintln!("  {}", "─".repeat(45));
            eprintln!("  Repository : {}", repo);
            eprintln!("  Reason     : {}", decision.reason);
            eprintln!("  Audit ID   : {}", entry.id);
            eprintln!("\n  Clone aborted. Contact your security team to request an exception.");
            std::process::exit(1);
        }
    }
}

async fn check_command(repo: &str, policy_path: Option<&str>) -> Result<()> {
    let (owner, name) = parse_repo(repo)?;

    let config = policy::Config::load(policy_path)?;
    let token = std::env::var("GITGATE_GITHUB_TOKEN").ok().filter(|t| !t.is_empty());

    let meta = github::fetch_repo_meta(owner, name, token.as_deref()).await?;
    let decision = policy::evaluate(&config, &meta);

    println!("  Repository : {}", repo);
    println!("  License    : {}", meta.license_id().unwrap_or("none"));
    println!("  Age        : {} days", meta.age_days());
    println!("  Stars      : {}", meta.stargazers_count);
    println!("  Decision   : {}", match decision.action {
        policy::Action::Allow => "ALLOW",
        policy::Action::Block => "BLOCK",
    });
    println!("  Reason     : {}", decision.reason);

    if decision.action == policy::Action::Block {
        std::process::exit(1);
    }

    Ok(())
}

fn policy_show_command(policy_path: Option<&str>) -> Result<()> {
    let (config, resolved_path) = policy::Config::load_with_path(policy_path)?;

    println!("  Policy file : {}", resolved_path);
    println!("  License allowlist  : {}", if config.license_allowlist.is_empty() { "(any)".to_string() } else { config.license_allowlist.join(", ") });
    println!("  License blocklist  : {}", if config.license_blocklist.is_empty() { "(none)".to_string() } else { config.license_blocklist.join(", ") });
    println!("  No-license action  : {:?}", config.no_license_action);
    println!("  Min repo age       : {} days", config.min_repo_age_days);
    println!("  Min stars          : {}", config.min_star_count);
    println!("  Org allowlist      : {}", if config.org_allowlist.is_empty() { "(none)".to_string() } else { config.org_allowlist.join(", ") });
    println!("  Org blocklist      : {}", if config.org_blocklist.is_empty() { "(none)".to_string() } else { config.org_blocklist.join(", ") });
    println!("  Exceptions         : {}", if config.exceptions.is_empty() { "(none)".to_string() } else { config.exceptions.join(", ") });
    println!("  Audit log          : {}", config.audit_log_path);

    Ok(())
}

fn parse_repo(repo: &str) -> Result<(&str, &str)> {
    let parts: Vec<&str> = repo.splitn(2, '/').collect();
    if parts.len() != 2 || parts[0].is_empty() || parts[1].is_empty() {
        anyhow::bail!("invalid repo format — expected owner/repo, got: {}", repo);
    }
    Ok((parts[0], parts[1]))
}
