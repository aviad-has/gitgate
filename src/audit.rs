use anyhow::Result;
use serde::Serialize;
use std::io::Write;

use crate::github::RepoMeta;
use crate::policy::{Action, Decision};

#[derive(Serialize)]
pub struct Entry {
    pub id: String,
    pub timestamp: String,
    pub action: Action,
    pub repo: String,
    pub license: Option<String>,
    pub repo_age_days: i64,
    pub stars: u64,
    pub reasons: Vec<String>,
    pub gitgate_version: &'static str,
}

impl Entry {
    pub fn new(repo: &str, meta: &RepoMeta, decision: &Decision) -> Self {
        let ts = chrono::Utc::now();
        let id = format!("gg-{}", uuid::Uuid::new_v4());

        Entry {
            id,
            timestamp: ts.to_rfc3339(),
            action: decision.action.clone(),
            repo: repo.to_string(),
            license: meta.license_id().map(|s| s.to_string()),
            repo_age_days: meta.age_days(),
            stars: meta.stargazers_count,
            reasons: decision.reasons.clone(),
            gitgate_version: env!("CARGO_PKG_VERSION"),
        }
    }

    pub fn write(&self, path: &str) -> Result<()> {
        let line = serde_json::to_string(self)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)?;
        writeln!(file, "{}", line)?;
        Ok(())
    }
}
