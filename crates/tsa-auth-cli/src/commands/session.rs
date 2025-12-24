use anyhow::Result;
use colored::Colorize;
use tabled::{Table, Tabled};

use tsa_auth_proto::{
    timestamp_to_datetime, ListSessionsRequest, RevokeAllSessionsRequest, RevokeSessionRequest,
};

use crate::client::{status_to_error, TsaClient};

#[derive(Tabled)]
struct SessionDisplay {
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

pub async fn list(client: &TsaClient) -> Result<()> {
    let mut session_client = client.session_client().await?;
    let request = client.auth_request(ListSessionsRequest {});

    let response = session_client
        .list_sessions(request)
        .await
        .map_err(status_to_error)?
        .into_inner();

    if response.sessions.is_empty() {
        println!("{}", "No active sessions".yellow());
        return Ok(());
    }

    let sessions: Vec<SessionDisplay> = response
        .sessions
        .into_iter()
        .map(|s| {
            let expires_at = timestamp_to_datetime(s.expires_at);
            let created_at = timestamp_to_datetime(s.created_at);
            SessionDisplay {
                id: s.id,
                expires_at: expires_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                created_at: created_at.format("%Y-%m-%d %H:%M:%S").to_string(),
                ip_address: s.ip_address,
                user_agent: s.user_agent,
            }
        })
        .collect();

    println!("{}", "Active Sessions".blue().bold());
    println!();
    let table = Table::new(&sessions).to_string();
    println!("{}", table);

    Ok(())
}

pub async fn revoke(client: &TsaClient, id: &str) -> Result<()> {
    let mut session_client = client.session_client().await?;

    let inner = RevokeSessionRequest {
        session_id: id.to_string(),
    };
    let request = client.auth_request(inner);

    session_client
        .revoke_session(request)
        .await
        .map_err(status_to_error)?;

    println!("{}", "Session revoked successfully!".green().bold());

    Ok(())
}

pub async fn revoke_all(client: &TsaClient) -> Result<()> {
    let mut session_client = client.session_client().await?;
    let request = client.auth_request(RevokeAllSessionsRequest {});

    session_client
        .revoke_all_sessions(request)
        .await
        .map_err(status_to_error)?;

    println!("{}", "All other sessions revoked!".green().bold());

    Ok(())
}
