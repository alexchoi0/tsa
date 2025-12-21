use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tabled::{Table, Tabled};

use crate::client::TsaClient;

#[derive(Deserialize, Tabled)]
struct ApiKeyResponse {
    id: String,
    name: String,
    prefix: String,
    #[tabled(display_with = "display_scopes")]
    scopes: Vec<String>,
    #[tabled(display_with = "display_option")]
    expires_at: Option<String>,
    #[tabled(display_with = "display_option")]
    last_used_at: Option<String>,
    created_at: String,
}

fn display_scopes(scopes: &Vec<String>) -> String {
    if scopes.is_empty() {
        "-".to_string()
    } else {
        scopes.join(", ")
    }
}

fn display_option(opt: &Option<String>) -> String {
    opt.as_deref().unwrap_or("-").to_string()
}

#[derive(Deserialize)]
struct ApiKeyCreatedResponse {
    key: ApiKeyResponse,
    secret: String,
}

#[derive(Deserialize)]
struct MessageResponse {
    #[allow(dead_code)]
    message: String,
}

pub async fn list(client: &TsaClient) -> Result<()> {
    let keys: Vec<ApiKeyResponse> = client.get("/users/me/api-keys").await?;

    if keys.is_empty() {
        println!("{}", "No API keys found".yellow());
        return Ok(());
    }

    println!("{}", "API Keys".blue().bold());
    println!();
    let table = Table::new(&keys).to_string();
    println!("{}", table);

    Ok(())
}

#[derive(Serialize)]
struct CreateApiKeyRequest {
    name: String,
    scopes: Option<Vec<String>>,
    expires_in_days: Option<i64>,
}

pub async fn create(
    client: &TsaClient,
    name: &str,
    scopes: Option<Vec<String>>,
    expires_days: Option<i64>,
) -> Result<()> {
    let req = CreateApiKeyRequest {
        name: name.to_string(),
        scopes,
        expires_in_days: expires_days,
    };

    let response: ApiKeyCreatedResponse = client.post("/users/me/api-keys", &req).await?;

    println!("{}", "API key created successfully!".green().bold());
    println!();
    println!("  {} {}", "ID:".dimmed(), response.key.id);
    println!("  {} {}", "Name:".dimmed(), response.key.name);
    println!("  {} {}", "Prefix:".dimmed(), response.key.prefix);
    println!();
    println!(
        "  {} {}",
        "Secret:".yellow().bold(),
        response.secret.cyan().bold()
    );
    println!();
    println!(
        "{}",
        "Save this secret now! It will not be shown again.".yellow()
    );

    Ok(())
}

#[derive(Serialize)]
struct UpdateApiKeyRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scopes: Option<Vec<String>>,
}

pub async fn update(
    client: &TsaClient,
    id: &str,
    name: Option<String>,
    scopes: Option<Vec<String>>,
) -> Result<()> {
    let req = UpdateApiKeyRequest { name, scopes };

    let key: ApiKeyResponse = client
        .put(&format!("/users/me/api-keys/{}", id), &req)
        .await?;

    println!("{}", "API key updated successfully!".green().bold());
    println!();
    println!("  {} {}", "ID:".dimmed(), key.id);
    println!("  {} {}", "Name:".dimmed(), key.name);
    println!("  {} {}", "Prefix:".dimmed(), key.prefix);
    if !key.scopes.is_empty() {
        println!("  {} {}", "Scopes:".dimmed(), key.scopes.join(", "));
    }

    Ok(())
}

pub async fn delete(client: &TsaClient, id: &str) -> Result<()> {
    let _: MessageResponse = client.delete(&format!("/users/me/api-keys/{}", id)).await?;

    println!("{}", "API key deleted successfully!".green().bold());

    Ok(())
}
