use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::github::RepoMeta;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoLicenseAction {
    Block,
    Allow,
}

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub license_allowlist: Vec<String>,
    #[serde(default)]
    pub license_blocklist: Vec<String>,
    #[serde(default = "default_no_license_action")]
    pub no_license_action: NoLicenseAction,
    #[serde(default = "default_min_age")]
    pub min_repo_age_days: i64,
    #[serde(default)]
    pub min_star_count: u64,
    #[serde(default)]
    pub org_allowlist: Vec<String>,
    #[serde(default)]
    pub org_blocklist: Vec<String>,
    #[serde(default)]
    pub exceptions: Vec<String>,
    #[serde(default = "default_audit_path")]
    pub audit_log_path: String,
}

fn default_no_license_action() -> NoLicenseAction {
    NoLicenseAction::Block
}
fn default_min_age() -> i64 {
    180
}
fn default_audit_path() -> String {
    "audit.jsonl".to_string()
}

impl Config {
    pub fn load(path: Option<&str>) -> Result<Self> {
        Ok(Self::load_with_path(path)?.0)
    }

    pub fn load_with_path(path: Option<&str>) -> Result<(Self, String)> {
        if let Some(p) = path {
            if !Path::new(p).exists() {
                anyhow::bail!("policy file not found: {}", p);
            }
            let config = serde_yaml::from_str(&std::fs::read_to_string(p)?)?;
            return Ok((config, p.to_string()));
        }

        for p in Self::search_paths() {
            if Path::new(&p).exists() {
                let config = serde_yaml::from_str(&std::fs::read_to_string(&p)?)?;
                return Ok((config, p));
            }
        }

        anyhow::bail!(
            "no policy file found. Searched:\n{}\n\nCreate a policy file or set GITGATE_POLICY_FILE.",
            Self::search_paths().join("\n")
        )
    }

    fn search_paths() -> Vec<String> {
        let mut paths = Vec::new();

        // Env var
        if let Ok(p) = std::env::var("GITGATE_POLICY_FILE") {
            if !p.is_empty() {
                paths.push(p);
                return paths; // env var is authoritative, skip rest
            }
        }

        // System-wide path (admin-deployed, read-only to users)
        #[cfg(target_os = "windows")]
        paths.push(r"C:\ProgramData\gitgate\policy.yaml".to_string());
        #[cfg(not(target_os = "windows"))]
        paths.push("/etc/gitgate/policy.yaml".to_string());

        // Current directory (dev/local use)
        paths.push("gitgate-policy.yaml".to_string());
        paths.push("gitgate-policy.yml".to_string());

        paths
    }
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Action {
    Allow,
    Block,
}

#[derive(Debug)]
pub struct Decision {
    pub action: Action,
    pub reason: String,
    pub reasons: Vec<String>,
}

pub fn evaluate(config: &Config, meta: &RepoMeta) -> Decision {
    let owner = meta.owner.login.to_lowercase();
    let repo = meta.full_name.to_lowercase();

    // Exception list — explicit override for specific repos
    if config.exceptions.iter().any(|e| e.to_lowercase() == repo) {
        return Decision {
            action: Action::Allow,
            reason: format!("'{}' is in the exception list", repo),
            reasons: vec!["exception".to_string()],
        };
    }

    // Org blocklist — block regardless of anything else
    if config.org_blocklist.iter().any(|o| o.to_lowercase() == owner) {
        return Decision {
            action: Action::Block,
            reason: format!("org '{}' is blocklisted", owner),
            reasons: vec!["org_blocklisted".to_string()],
        };
    }

    // Org allowlist — bypass all further checks
    if config.org_allowlist.iter().any(|o| o.to_lowercase() == owner) {
        return Decision {
            action: Action::Allow,
            reason: format!("org '{}' is allowlisted", owner),
            reasons: vec!["org_allowlisted".to_string()],
        };
    }

    let mut blocks: Vec<String> = Vec::new();

    // License checks
    match meta.license_id() {
        None => {
            if matches!(config.no_license_action, NoLicenseAction::Block) {
                blocks.push("no_license".to_string());
            }
        }
        Some("NOASSERTION") | Some("NONE") => {
            blocks.push("license_unrecognized".to_string());
        }
        Some(spdx) => {
            let upper = spdx.to_uppercase();
            if config.license_blocklist.iter().any(|l| l.to_uppercase() == upper) {
                blocks.push(format!("license_blocklisted:{}", spdx));
            } else if !config.license_allowlist.is_empty()
                && !config.license_allowlist.iter().any(|l| l.to_uppercase() == upper)
            {
                blocks.push(format!("license_not_allowed:{}", spdx));
            }
        }
    }

    // Age check
    let age = meta.age_days();
    if age < config.min_repo_age_days {
        blocks.push(format!("repo_too_new:{}days", age));
    }

    // Star check
    if meta.stargazers_count < config.min_star_count {
        blocks.push(format!("stars_below_threshold:{}", meta.stargazers_count));
    }

    if blocks.is_empty() {
        Decision {
            action: Action::Allow,
            reason: "all checks passed".to_string(),
            reasons: vec!["allowed".to_string()],
        }
    } else {
        Decision {
            action: Action::Block,
            reason: blocks[0].clone(),
            reasons: blocks,
        }
    }
}
