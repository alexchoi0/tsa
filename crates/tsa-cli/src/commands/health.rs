use anyhow::Result;
use colored::Colorize;
use serde::Deserialize;

use crate::client::TsaClient;

#[derive(Deserialize)]
struct HealthResponse {
    status: String,
    #[serde(default)]
    version: Option<String>,
}

pub async fn check(client: &TsaClient) -> Result<()> {
    let health: HealthResponse = client.get("/health").await?;

    if health.status == "ok" || health.status == "healthy" {
        println!("{} {}", "Status:".dimmed(), health.status.green().bold());
    } else {
        println!("{} {}", "Status:".dimmed(), health.status.yellow().bold());
    }

    if let Some(version) = health.version {
        println!("{} {}", "Version:".dimmed(), version);
    }

    Ok(())
}
