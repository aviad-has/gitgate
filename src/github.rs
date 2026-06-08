use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RepoMeta {
    pub license: Option<License>,
    pub created_at: String,
    pub stargazers_count: u64,
    pub owner: Owner,
}

#[derive(Debug, Deserialize)]
pub struct License {
    pub spdx_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct Owner {
    pub login: String,
}

impl RepoMeta {
    pub fn license_id(&self) -> Option<&str> {
        self.license.as_ref()?.spdx_id.as_deref()
    }

    pub fn age_days(&self) -> i64 {
        let created = chrono::DateTime::parse_from_rfc3339(&self.created_at)
            .unwrap_or_default()
            .with_timezone(&chrono::Utc);
        (chrono::Utc::now() - created).num_days()
    }
}

pub async fn fetch_repo_meta(owner: &str, repo: &str, token: Option<&str>) -> Result<RepoMeta> {
    let url = format!("https://api.github.com/repos/{}/{}", owner, repo);

    let client = reqwest::Client::builder()
        .user_agent("gitgate/0.1")
        .build()?;

    let mut req = client.get(&url);
    if let Some(t) = token {
        req = req.bearer_auth(t);
    }

    let resp = req.send().await?;

    if !resp.status().is_success() {
        anyhow::bail!(
            "GitHub API returned {}: {}",
            resp.status(),
            resp.text().await.unwrap_or_default()
        );
    }

    Ok(resp.json::<RepoMeta>().await?)
}
