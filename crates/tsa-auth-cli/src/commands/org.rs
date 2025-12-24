use anyhow::Result;
use colored::Colorize;
use tabled::{Table, Tabled};

use tsa_auth_proto::{
    timestamp_to_datetime, AddMemberRequest, CreateOrganizationRequest, DeleteOrganizationRequest,
    GetOrganizationRequest, ListMembersRequest, ListOrganizationsRequest, RemoveMemberRequest,
    UpdateMemberRequest as ProtoUpdateMemberRequest, UpdateOrganizationRequest,
};

use crate::client::{status_to_error, TsaClient};

#[derive(Tabled)]
struct OrgDisplay {
    id: String,
    name: String,
    slug: String,
    created_at: String,
}

pub async fn list(client: &TsaClient) -> Result<()> {
    let mut org_client = client.org_client().await?;
    let request = client.auth_request(ListOrganizationsRequest {});

    let response = org_client
        .list_organizations(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    if response.organizations.is_empty() {
        println!("{}", "No organizations found".yellow());
        return Ok(());
    }

    let orgs: Vec<OrgDisplay> = response
        .organizations
        .into_iter()
        .map(|o| {
            let created_at = timestamp_to_datetime(o.created_at);
            OrgDisplay {
                id: o.id,
                name: o.name,
                slug: o.slug,
                created_at: created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
            }
        })
        .collect();

    println!("{}", "Organizations".blue().bold());
    println!();
    let table = Table::new(&orgs).to_string();
    println!("{}", table);

    Ok(())
}

pub async fn create(client: &TsaClient, name: &str, slug: &str) -> Result<()> {
    let mut org_client = client.org_client().await?;

    let inner = CreateOrganizationRequest {
        name: name.to_string(),
        slug: slug.to_string(),
    };
    let request = client.auth_request(inner);

    let response = org_client
        .create_organization(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    let org = response.organization.unwrap();

    println!("{}", "Organization created successfully!".green().bold());
    println!();
    println!("  {} {}", "ID:".dimmed(), org.id);
    println!("  {} {}", "Name:".dimmed(), org.name);
    println!("  {} {}", "Slug:".dimmed(), org.slug);

    Ok(())
}

pub async fn get(client: &TsaClient, slug: &str) -> Result<()> {
    let mut org_client = client.org_client().await?;

    let request = GetOrganizationRequest {
        slug: slug.to_string(),
    };

    let response = org_client
        .get_organization(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    let org = response.organization.unwrap();

    println!("{}", "Organization".blue().bold());
    println!();
    println!("  {} {}", "ID:".dimmed(), org.id);
    println!("  {} {}", "Name:".dimmed(), org.name);
    println!("  {} {}", "Slug:".dimmed(), org.slug);
    if let Some(logo) = org.logo {
        println!("  {} {}", "Logo:".dimmed(), logo);
    }
    let created_at = timestamp_to_datetime(org.created_at);
    println!(
        "  {} {}",
        "Created:".dimmed(),
        created_at.format("%Y-%m-%d %H:%M:%S UTC")
    );

    Ok(())
}

pub async fn update(
    client: &TsaClient,
    id: &str,
    name: Option<&str>,
    logo: Option<&str>,
) -> Result<()> {
    let mut org_client = client.org_client().await?;

    let inner = UpdateOrganizationRequest {
        id: id.to_string(),
        name: name.map(|n| n.to_string()),
        logo: logo.map(|l| l.to_string()),
    };
    let request = client.auth_request(inner);

    let response = org_client
        .update_organization(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    let org = response.organization.unwrap();

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
    let mut org_client = client.org_client().await?;

    let inner = DeleteOrganizationRequest { id: id.to_string() };
    let request = client.auth_request(inner);

    org_client
        .delete_organization(request)
        .await
        .map_err(status_to_error)?;

    println!("{}", "Organization deleted successfully!".green().bold());

    Ok(())
}

pub async fn members(client: &TsaClient, id: &str) -> Result<()> {
    let mut org_client = client.org_client().await?;

    let request = ListMembersRequest {
        organization_id: id.to_string(),
    };

    let response = org_client
        .list_members(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    if response.members.is_empty() {
        println!("{}", "No members found".yellow());
        return Ok(());
    }

    println!("{}", "Organization Members".blue().bold());
    println!();

    for member in response.members {
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

pub async fn add_member(client: &TsaClient, org_id: &str, user_id: &str, role: &str) -> Result<()> {
    let mut org_client = client.org_client().await?;

    let inner = AddMemberRequest {
        organization_id: org_id.to_string(),
        user_id: user_id.to_string(),
        role: role.to_string(),
    };
    let request = client.auth_request(inner);

    org_client
        .add_member(request)
        .await
        .map_err(status_to_error)?;

    println!("{}", "Member added successfully!".green().bold());

    Ok(())
}

pub async fn update_member(
    client: &TsaClient,
    org_id: &str,
    user_id: &str,
    role: &str,
) -> Result<()> {
    let mut org_client = client.org_client().await?;

    let inner = ProtoUpdateMemberRequest {
        organization_id: org_id.to_string(),
        user_id: user_id.to_string(),
        role: role.to_string(),
    };
    let request = client.auth_request(inner);

    let response = org_client
        .update_member(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    let member = response.member.unwrap();

    println!("{}", "Member role updated successfully!".green().bold());
    println!();
    println!("  {} {}", "User ID:".dimmed(), member.user_id);
    println!("  {} {}", "New Role:".dimmed(), member.role.cyan());

    Ok(())
}

pub async fn remove_member(client: &TsaClient, org_id: &str, user_id: &str) -> Result<()> {
    let mut org_client = client.org_client().await?;

    let inner = RemoveMemberRequest {
        organization_id: org_id.to_string(),
        user_id: user_id.to_string(),
    };
    let request = client.auth_request(inner);

    org_client
        .remove_member(request)
        .await
        .map_err(status_to_error)?;

    println!("{}", "Member removed successfully!".green().bold());

    Ok(())
}
