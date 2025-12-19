use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};

use crate::client::TsaClient;

#[derive(Deserialize)]
struct UserResponse {
    id: String,
    email: String,
    email_verified: bool,
    phone: Option<String>,
    phone_verified: bool,
    name: Option<String>,
    created_at: String,
}

pub async fn me(client: &TsaClient) -> Result<()> {
    let user: UserResponse = client.get("/users/me").await?;

    println!("{}", "Current User".blue().bold());
    println!();
    println!("  {} {}", "ID:".dimmed(), user.id);
    println!("  {} {}", "Email:".dimmed(), user.email);
    println!(
        "  {} {}",
        "Email Verified:".dimmed(),
        if user.email_verified {
            "Yes".green()
        } else {
            "No".yellow()
        }
    );
    if let Some(phone) = user.phone {
        println!("  {} {}", "Phone:".dimmed(), phone);
        println!(
            "  {} {}",
            "Phone Verified:".dimmed(),
            if user.phone_verified {
                "Yes".green()
            } else {
                "No".yellow()
            }
        );
    }
    if let Some(name) = user.name {
        println!("  {} {}", "Name:".dimmed(), name);
    }
    println!("  {} {}", "Created:".dimmed(), user.created_at);

    Ok(())
}

#[derive(Serialize)]
struct UpdateUserRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    phone: Option<String>,
}

pub async fn update(client: &TsaClient, name: Option<&str>, phone: Option<&str>) -> Result<()> {
    let req = UpdateUserRequest {
        name: name.map(|n| n.to_string()),
        phone: phone.map(|p| p.to_string()),
    };

    let user: UserResponse = client.put("/users/me", &req).await?;

    println!("{}", "User updated successfully!".green().bold());
    println!();
    println!("  {} {}", "ID:".dimmed(), user.id);
    println!("  {} {}", "Email:".dimmed(), user.email);
    if let Some(name) = user.name {
        println!("  {} {}", "Name:".dimmed(), name);
    }
    if let Some(phone) = user.phone {
        println!("  {} {}", "Phone:".dimmed(), phone);
    }

    Ok(())
}

#[derive(Serialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

#[derive(Deserialize)]
struct MessageResponse {
    message: String,
}

pub async fn change_password(client: &TsaClient, current: &str, new: &str) -> Result<()> {
    let req = ChangePasswordRequest {
        current_password: current.to_string(),
        new_password: new.to_string(),
    };

    let _: MessageResponse = client.put("/auth/password", &req).await?;

    println!("{}", "Password changed successfully!".green().bold());

    Ok(())
}
