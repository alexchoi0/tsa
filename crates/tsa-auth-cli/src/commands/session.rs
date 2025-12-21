use anyhow::Result;
use colored::Colorize;
use serde::Deserialize;
use tabled::{Table, Tabled};

use crate::client::TsaClient;

#[derive(Deserialize, Tabled)]
struct SessionResponse {
    id: String,
    expires_at: String,
    created_at: String,
    #[tabled(display_with = "display_option")]
    ip_address: Option<String>,
    #[tabled(display_with = "display_option")]
    user_agent: Option<String>,
}

fn display_option(opt: &Option<String>) -> String {
    opt.as_deref().unwrap_or("-").to_string()
}

#[derive(Deserialize)]
struct MessageResponse {
    #[allow(dead_code)]
    message: String,
}

pub async fn list(client: &TsaClient) -> Result<()> {
    let sessions: Vec<SessionResponse> = client.get("/users/me/sessions").await?;

    if sessions.is_empty() {
        println!("{}", "No active sessions".yellow());
        return Ok(());
    }

    println!("{}", "Active Sessions".blue().bold());
    println!();
    let table = Table::new(&sessions).to_string();
    println!("{}", table);

    Ok(())
}

pub async fn revoke(client: &TsaClient, id: &str) -> Result<()> {
    let _: MessageResponse = client.delete(&format!("/users/me/sessions/{}", id)).await?;

    println!("{}", "Session revoked successfully!".green().bold());

    Ok(())
}

pub async fn revoke_all(client: &TsaClient) -> Result<()> {
    let _: MessageResponse = client.delete("/users/me/sessions").await?;

    println!("{}", "All other sessions revoked!".green().bold());

    Ok(())
}
