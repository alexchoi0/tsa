use anyhow::Result;
use colored::Colorize;

use tsa_auth_proto::{GetCurrentUserRequest, SigninRequest, SignoutRequest, SignupRequest};

use crate::client::{status_to_error, TsaClient};
use crate::config::CliConfig;

pub async fn signup(
    client: &TsaClient,
    email: &str,
    password: &str,
    name: Option<&str>,
) -> Result<()> {
    let mut auth_client = client.auth_client().await?;

    let request = SignupRequest {
        email: email.to_string(),
        password: password.to_string(),
        name: name.map(|n| n.to_string()),
        ip_address: None,
        user_agent: None,
    };

    let response = auth_client
        .signup(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    let user = response.user.unwrap();

    let mut config = CliConfig::load()?;
    let ctx_name = config
        .current_context
        .clone()
        .unwrap_or_else(|| "default".to_string());
    config.set_token(Some(response.token))?;

    println!("{}", "Account created successfully!".green().bold());
    println!();
    println!("  {} {}", "Context:".dimmed(), ctx_name.cyan());
    println!("  {} {}", "User ID:".dimmed(), user.id);
    println!("  {} {}", "Email:".dimmed(), user.email);
    if let Some(name) = user.name {
        println!("  {} {}", "Name:".dimmed(), name);
    }

    Ok(())
}

pub async fn signin(client: &TsaClient, email: &str, password: &str) -> Result<()> {
    let mut auth_client = client.auth_client().await?;

    let request = SigninRequest {
        email: email.to_string(),
        password: password.to_string(),
        ip_address: None,
        user_agent: None,
    };

    let response = auth_client
        .signin(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    let user = response.user.unwrap();

    let mut config = CliConfig::load()?;
    let ctx_name = config
        .current_context
        .clone()
        .unwrap_or_else(|| "default".to_string());
    config.set_token(Some(response.token))?;

    println!("{}", "Signed in successfully!".green().bold());
    println!();
    println!("  {} {}", "Context:".dimmed(), ctx_name.cyan());
    println!("  {} {}", "User ID:".dimmed(), user.id);
    println!("  {} {}", "Email:".dimmed(), user.email);

    Ok(())
}

pub async fn signout(client: &TsaClient) -> Result<()> {
    let mut auth_client = client.auth_client().await?;

    let request = client.auth_request(SignoutRequest {});

    auth_client
        .signout(request)
        .await
        .map_err(status_to_error)?;

    let mut config = CliConfig::load()?;
    let ctx_name = config
        .current_context
        .clone()
        .unwrap_or_else(|| "default".to_string());
    config.set_token(None)?;

    println!("{}", "Signed out successfully!".green().bold());
    println!("  {} {}", "Context:".dimmed(), ctx_name.cyan());

    Ok(())
}

pub async fn status(client: &TsaClient) -> Result<()> {
    let config = CliConfig::load()?;
    let ctx_name = config
        .current_context
        .clone()
        .unwrap_or_else(|| "default".to_string());

    println!("{}", "Context".blue().bold());
    println!("  {} {}", "Name:".dimmed(), ctx_name.cyan());
    if let Some(ctx) = config.current_context() {
        println!("  {} {}", "Server:".dimmed(), ctx.server_url);
    }
    println!();

    if config.token().is_none() {
        println!("{}", "Not signed in".yellow().bold());
        return Ok(());
    }

    let mut user_client = client.user_client().await?;
    let request = client.auth_request(GetCurrentUserRequest {});

    match user_client.get_current_user(request).await {
        Ok(response) => {
            let user = response.into_inner().user.unwrap();
            println!("{}", "Signed in".green().bold());
            println!();
            println!("  {} {}", "User ID:".dimmed(), user.id);
            println!("  {} {}", "Email:".dimmed(), user.email);
            if let Some(name) = user.name {
                println!("  {} {}", "Name:".dimmed(), name);
            }
        }
        Err(_) => {
            println!("{}", "Session expired or invalid".yellow().bold());
            let mut config = CliConfig::load()?;
            config.set_token(None)?;
        }
    }

    Ok(())
}
