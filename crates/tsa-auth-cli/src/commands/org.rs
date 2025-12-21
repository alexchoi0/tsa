use anyhow::Result;
use colored::Colorize;
use serde::{Deserialize, Serialize};
use tabled::{Table, Tabled};

use crate::client::TsaClient;

#[derive(Deserialize, Tabled)]
struct OrgResponse {
    id: String,
    name: String,
    slug: String,
    #[tabled(skip)]
    logo: Option<String>,
    created_at: String,
}

#[derive(Deserialize)]
struct MemberResponse {
    #[allow(dead_code)]
    id: String,
    user_id: String,
    role: String,
    user: Option<UserResponse>,
    #[allow(dead_code)]
    created_at: String,
}

#[derive(Deserialize)]
struct UserResponse {
    #[allow(dead_code)]
    id: String,
    email: String,
    name: Option<String>,
}

#[derive(Deserialize)]
struct MessageResponse {
    #[allow(dead_code)]
    message: String,
}

pub async fn list(client: &TsaClient) -> Result<()> {
    let orgs: Vec<OrgResponse> = client.get("/organizations").await?;

    if orgs.is_empty() {
        println!("{}", "No organizations found".yellow());
        return Ok(());
    }

    println!("{}", "Organizations".blue().bold());
    println!();
    let table = Table::new(&orgs).to_string();
    println!("{}", table);

    Ok(())
}

#[derive(Serialize)]
struct CreateOrgRequest {
    name: String,
    slug: String,
}

pub async fn create(client: &TsaClient, name: &str, slug: &str) -> Result<()> {
    let req = CreateOrgRequest {
        name: name.to_string(),
        slug: slug.to_string(),
    };

    let org: OrgResponse = client.post("/organizations", &req).await?;

    println!("{}", "Organization created successfully!".green().bold());
    println!();
    println!("  {} {}", "ID:".dimmed(), org.id);
    println!("  {} {}", "Name:".dimmed(), org.name);
    println!("  {} {}", "Slug:".dimmed(), org.slug);

    Ok(())
}

pub async fn get(client: &TsaClient, slug: &str) -> Result<()> {
    let org: OrgResponse = client.get(&format!("/organizations/{}", slug)).await?;

    println!("{}", "Organization".blue().bold());
    println!();
    println!("  {} {}", "ID:".dimmed(), org.id);
    println!("  {} {}", "Name:".dimmed(), org.name);
    println!("  {} {}", "Slug:".dimmed(), org.slug);
    if let Some(logo) = org.logo {
        println!("  {} {}", "Logo:".dimmed(), logo);
    }
    println!("  {} {}", "Created:".dimmed(), org.created_at);

    Ok(())
}

#[derive(Serialize)]
struct UpdateOrgRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    logo: Option<String>,
}

pub async fn update(client: &TsaClient, id: &str, name: Option<&str>, logo: Option<&str>) -> Result<()> {
    let req = UpdateOrgRequest {
        name: name.map(|n| n.to_string()),
        logo: logo.map(|l| l.to_string()),
    };

    let org: OrgResponse = client.put(&format!("/organizations/{}", id), &req).await?;

    println!("{}", "Organization updated successfully!".green().bold());
    println!();
    println!("  {} {}", "ID:".dimmed(), org.id);
    println!("  {} {}", "Name:".dimmed(), org.name);
    println!("  {} {}", "Slug:".dimmed(), org.slug);
    if let Some(logo) = org.logo {
        println!("  {} {}", "Logo:".dimmed(), logo);
    }

    Ok(())
}

pub async fn delete(client: &TsaClient, id: &str) -> Result<()> {
    let _: MessageResponse = client.delete(&format!("/organizations/{}", id)).await?;

    println!("{}", "Organization deleted successfully!".green().bold());

    Ok(())
}

pub async fn members(client: &TsaClient, id: &str) -> Result<()> {
    let members: Vec<MemberResponse> = client.get(&format!("/organizations/{}/members", id)).await?;

    if members.is_empty() {
        println!("{}", "No members found".yellow());
        return Ok(());
    }

    println!("{}", "Organization Members".blue().bold());
    println!();

    for member in members {
        let email = member
            .user
            .as_ref()
            .map(|u| u.email.as_str())
            .unwrap_or("Unknown");
        let name = member
            .user
            .as_ref()
            .and_then(|u| u.name.as_deref())
            .unwrap_or("-");

        println!(
            "  {} {} ({}) - {}",
            member.role.cyan(),
            email,
            name.dimmed(),
            member.user_id.dimmed()
        );
    }

    Ok(())
}

#[derive(Serialize)]
struct AddMemberRequest {
    user_id: String,
    role: String,
}

pub async fn add_member(client: &TsaClient, org_id: &str, user_id: &str, role: &str) -> Result<()> {
    let req = AddMemberRequest {
        user_id: user_id.to_string(),
        role: role.to_string(),
    };

    let _: MemberResponse = client.post(&format!("/organizations/{}/members", org_id), &req).await?;

    println!("{}", "Member added successfully!".green().bold());

    Ok(())
}

#[derive(Serialize)]
struct UpdateMemberRequest {
    role: String,
}

pub async fn update_member(client: &TsaClient, org_id: &str, user_id: &str, role: &str) -> Result<()> {
    let req = UpdateMemberRequest {
        role: role.to_string(),
    };

    let member: MemberResponse = client
        .put(&format!("/organizations/{}/members/{}", org_id, user_id), &req)
        .await?;

    println!("{}", "Member role updated successfully!".green().bold());
    println!();
    println!("  {} {}", "User ID:".dimmed(), member.user_id);
    println!("  {} {}", "New Role:".dimmed(), member.role.cyan());

    Ok(())
}

pub async fn remove_member(client: &TsaClient, org_id: &str, user_id: &str) -> Result<()> {
    let _: MessageResponse = client
        .delete(&format!("/organizations/{}/members/{}", org_id, user_id))
        .await?;

    println!("{}", "Member removed successfully!".green().bold());

    Ok(())
}
