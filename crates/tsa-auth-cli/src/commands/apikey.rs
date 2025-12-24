use anyhow::Result;
use colored::Colorize;
use tabled::{Table, Tabled};

use tsa_auth_proto::{
    timestamp_to_datetime, CreateApiKeyRequest, DeleteApiKeyRequest, ListApiKeysRequest,
    UpdateApiKeyRequest as ProtoUpdateApiKeyRequest,
};

use crate::client::{status_to_error, TsaClient};

#[derive(Tabled)]
struct ApiKeyDisplay {
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

fn display_scopes(scopes: &[String]) -> String {
    if scopes.is_empty() {
        "-".to_string()
    } else {
        scopes.join(", ")
    }
}

fn display_option(opt: &Option<String>) -> String {
    opt.as_deref().unwrap_or("-").to_string()
}

pub async fn list(client: &TsaClient) -> Result<()> {
    let mut apikey_client = client.apikey_client().await?;
    let request = client.auth_request(ListApiKeysRequest {});

    let response = apikey_client
        .list_api_keys(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    if response.api_keys.is_empty() {
        println!("{}", "No API keys found".yellow());
        return Ok(());
    }

    let keys: Vec<ApiKeyDisplay> = response
        .api_keys
        .into_iter()
        .map(|k| {
            let created_at = timestamp_to_datetime(k.created_at);
            let expires_at = k.expires_at.map(|t| {
                let dt = timestamp_to_datetime(Some(t));
                dt.format("%Y-%m-%d %H:%M:%S").to_string()
            });
            let last_used_at = k.last_used_at.map(|t| {
                let dt = timestamp_to_datetime(Some(t));
                dt.format("%Y-%m-%d %H:%M:%S").to_string()
            });
            ApiKeyDisplay {
                id: k.id,
                name: k.name,
                prefix: k.prefix,
                scopes: k.scopes,
                expires_at,
                last_used_at,
                created_at: created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            }
        })
        .collect();

    println!("{}", "API Keys".blue().bold());
    println!();
    let table = Table::new(&keys).to_string();
    println!("{}", table);

    Ok(())
}

pub async fn create(
    client: &TsaClient,
    name: &str,
    scopes: Option<Vec<String>>,
    expires_days: Option<i64>,
) -> Result<()> {
    let mut apikey_client = client.apikey_client().await?;

    let inner = CreateApiKeyRequest {
        name: name.to_string(),
        scopes: scopes.unwrap_or_default(),
        expires_in_days: expires_days,
    };
    let request = client.auth_request(inner);

    let response = apikey_client
        .create_api_key(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    let key = response.api_key.unwrap();

    println!("{}", "API key created successfully!".green().bold());
    println!();
    println!("  {} {}", "ID:".dimmed(), key.id);
    println!("  {} {}", "Name:".dimmed(), key.name);
    println!("  {} {}", "Prefix:".dimmed(), key.prefix);
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

pub async fn update(
    client: &TsaClient,
    id: &str,
    name: Option<String>,
    scopes: Option<Vec<String>>,
) -> Result<()> {
    let mut apikey_client = client.apikey_client().await?;

    let inner = ProtoUpdateApiKeyRequest {
        id: id.to_string(),
        name,
        scopes: scopes.unwrap_or_default(),
    };
    let request = client.auth_request(inner);

    let response = apikey_client
        .update_api_key(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    let key = response.api_key.unwrap();

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
    let mut apikey_client = client.apikey_client().await?;

    let inner = DeleteApiKeyRequest { id: id.to_string() };
    let request = client.auth_request(inner);

    apikey_client
        .delete_api_key(request)
        .await
        .map_err(status_to_error)?;

    println!("{}", "API key deleted successfully!".green().bold());

    Ok(())
}
