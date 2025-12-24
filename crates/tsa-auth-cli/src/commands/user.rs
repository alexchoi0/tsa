use anyhow::Result;
use colored::Colorize;

use tsa_auth_proto::{
    timestamp_to_datetime, ChangePasswordRequest, GetCurrentUserRequest, UpdateCurrentUserRequest,
};

use crate::client::{status_to_error, TsaClient};

pub async fn me(client: &TsaClient) -> Result<()> {
    let mut user_client = client.user_client().await?;
    let request = client.auth_request(GetCurrentUserRequest {});

    let response = user_client
        .get_current_user(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    let user = response.user.unwrap();

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
    let created_at = timestamp_to_datetime(user.created_at);
    println!(
        "  {} {}",
        "Created:".dimmed(),
        created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    Ok(())
}

pub async fn update(client: &TsaClient, name: Option<&str>, phone: Option<&str>) -> Result<()> {
    let mut user_client = client.user_client().await?;

    let inner = UpdateCurrentUserRequest {
        name: name.map(|n| n.to_string()),
        phone: phone.map(|p| p.to_string()),
    };
    let request = client.auth_request(inner);

    let response = user_client
        .update_current_user(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    let user = response.user.unwrap();

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

pub async fn change_password(client: &TsaClient, current: &str, new: &str) -> Result<()> {
    let mut auth_client = client.auth_client().await?;

    let inner = ChangePasswordRequest {
        current_password: current.to_string(),
        new_password: new.to_string(),
        revoke_other_sessions: false,
    };
    let request = client.auth_request(inner);

    auth_client
        .change_password(request)
        .await
        .map_err(status_to_error)?;

    println!("{}", "Password changed successfully!".green().bold());

    Ok(())
}
