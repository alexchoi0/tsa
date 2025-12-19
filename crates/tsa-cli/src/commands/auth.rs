use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::client::TsaClient;
use crate::config::CliConfig;

#[derive(Serialize)]
struct SignupRequest {
    email: String,
    password: String,
    name: Option<String>,
}

#[derive(Serialize)]
struct SigninRequest {
    email: String,
    password: String,
}

#[derive(Deserialize)]
struct AuthResponse {
    user: UserResponse,
    token: String,
}

#[derive(Deserialize)]
struct UserResponse {
    id: String,
    email: String,
    name: Option<String>,
}

pub async fn signup(client: &TsaClient, email: &str, password: &str, name: Option<&str>) -> Result<()> {
    let req = SignupRequest {
        email: email.to_string(),
        password: password.to_string(),
        name: name.map(|n| n.to_string()),
    };

    let response: AuthResponse = client.post("/auth/signup", &req).await?;

    let mut config = CliConfig::load()?;
    config.set_token(Some(response.token))?;

    println!("{}", "Account created successfully!".green().bold());
    println!();
    println!("  {} {}", "User ID:".dimmed(), response.user.id);
    println!("  {} {}", "Email:".dimmed(), response.user.email);
    if let Some(name) = response.user.name {
        println!("  {} {}", "Name:".dimmed(), name);
    }

    Ok(())
}

pub async fn signin(client: &TsaClient, email: &str, password: &str) -> Result<()> {
    let req = SigninRequest {
        email: email.to_string(),
        password: password.to_string(),
    };

    let response: AuthResponse = client.post("/auth/signin", &req).await?;

    let mut config = CliConfig::load()?;
    config.set_token(Some(response.token))?;

    println!("{}", "Signed in successfully!".green().bold());
    println!();
    println!("  {} {}", "User ID:".dimmed(), response.user.id);
    println!("  {} {}", "Email:".dimmed(), response.user.email);

    Ok(())
}

pub async fn signout(client: &TsaClient) -> Result<()> {
    #[derive(Deserialize)]
    struct MessageResponse {
        message: String,
    }

    let _: MessageResponse = client.post("/auth/signout", &serde_json::json!({})).await?;

    let mut config = CliConfig::load()?;
    config.set_token(None)?;

    println!("{}", "Signed out successfully!".green().bold());

    Ok(())
}

pub async fn status(client: &TsaClient) -> Result<()> {
    let config = CliConfig::load()?;

    if config.token.is_none() {
        println!("{}", "Not signed in".yellow().bold());
        return Ok(());
    }

    match client.get::<UserResponse>("/users/me").await {
        Ok(user) => {
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
