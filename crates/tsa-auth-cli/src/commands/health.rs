use anyhow::Result;
use colored::Colorize;

use tsa_auth_proto::HealthCheckRequest;

use crate::client::{status_to_error, TsaClient};

pub async fn check(client: &TsaClient) -> Result<()> {
    let mut health_client = client.health_client().await?;

    let response = health_client
        .check(HealthCheckRequest {})
        .await
        .map_err(status_to_error)?
        .into_inner();

    if response.status == "ok" || response.status == "healthy" {
        println!("{} {}", "Status:".dimmed(), response.status.green().bold());
    } else {
        println!("{} {}", "Status:".dimmed(), response.status.yellow().bold());
    }

    if !response.version.is_empty() {
        println!("{} {}", "Version:".dimmed(), response.version);
    }

    Ok(())
}
