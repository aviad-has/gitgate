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
    pub allowed_licenses: Vec<String>,
    #[serde(default)]
    pub blocked_licenses: Vec<String>,
    #[serde(default = "default_no_license_action")]
    pub no_license_action: NoLicenseAction,
    #[serde(default = "default_min_age")]
    pub min_repo_age_days: i64,
    #[serde(default)]
    pub min_star_count: u64,
    #[serde(default)]
    pub org_whitelist: Vec<String>,
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
        let candidates: &[&str] = match path {
            Some(p) => &[p],
            None => &["gitgate-policy.yaml", "gitgate-policy.yml"],
        };
        for p in candidates {
            if Path::new(p).exists() {
                let content = std::fs::read_to_string(p)?;
                return Ok(serde_yaml::from_str(&content)?);
            }
        }
        if path.is_some() {
            anyhow::bail!("policy file not found: {}", path.unwrap());
        }
        // No config file found — use safe defaults
        Ok(serde_yaml::from_str("")?)
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

    // Whitelist check — bypass everything
    if config.org_whitelist.iter().any(|o| o.to_lowercase() == owner) {
        return Decision {
            action: Action::Allow,
            reason: format!("org '{}' is whitelisted", owner),
            reasons: vec!["org_whitelisted".to_string()],
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
            blocks.push("no_license".to_string());
        }
        Some(spdx) => {
            let upper = spdx.to_uppercase();
            if config.blocked_licenses.iter().any(|l| l.to_uppercase() == upper) {
                blocks.push(format!("license_blocked:{}", spdx));
            } else if !config.allowed_licenses.is_empty()
                && !config.allowed_licenses.iter().any(|l| l.to_uppercase() == upper)
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
