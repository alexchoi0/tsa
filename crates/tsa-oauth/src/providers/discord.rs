use async_trait::async_trait;
use oauth2::Scope;
use serde::Deserialize;
use tsa_core::{Result, TsaError};

use crate::{create_oauth_client, ConfiguredClient, OAuthProvider, OAuthUserInfo};

pub struct DiscordProvider {
    client: ConfiguredClient,
    scopes: Vec<Scope>,
}

impl DiscordProvider {
    pub fn new(client_id: &str, client_secret: &str, redirect_url: &str) -> Result<Self> {
        let client = create_oauth_client(
            client_id,
            client_secret,
            "https://discord.com/api/oauth2/authorize",
            "https://discord.com/api/oauth2/token",
            redirect_url,
        )?;

        Ok(Self {
            client,
            scopes: vec![
                Scope::new("identify".to_string()),
                Scope::new("email".to_string()),
            ],
        })
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes.into_iter().map(Scope::new).collect();
        self
    }
}

#[derive(Debug, Deserialize)]
struct DiscordUser {
    id: String,
    email: Option<String>,
    verified: Option<bool>,
    username: String,
    global_name: Option<String>,
    avatar: Option<String>,
}

impl DiscordUser {
    fn avatar_url(&self) -> Option<String> {
        self.avatar.as_ref().map(|hash| {
            format!("https://cdn.discordapp.com/avatars/{}/{}.png", self.id, hash)
        })
    }
}

#[async_trait]
impl OAuthProvider for DiscordProvider {
    fn name(&self) -> &'static str {
        "discord"
    }

    fn client(&self) -> &ConfiguredClient {
        &self.client
    }

    fn scopes(&self) -> Vec<Scope> {
        self.scopes.clone()
    }

    async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo> {
        let client = reqwest::Client::new();
        let response = client
            .get("https://discord.com/api/v10/users/@me")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        if !response.status().is_success() {
            return Err(TsaError::Internal(format!(
                "Failed to get user info: {}",
                response.status()
            )));
        }

        let user: DiscordUser = response
            .json()
            .await
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        let avatar_url = user.avatar_url();
        let name = user.global_name.or(Some(user.username));

        Ok(OAuthUserInfo {
            provider_user_id: user.id,
            email: user.email,
            email_verified: user.verified,
            name,
            image: avatar_url,
        })
    }
}
