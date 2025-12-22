use async_trait::async_trait;
use oauth2::Scope;
use serde::Deserialize;
use tsa_auth_core::{Result, TsaError};

use crate::{create_oauth_client, ConfiguredClient, OAuthProvider, OAuthUserInfo};

pub struct TwitchProvider {
    client: ConfiguredClient,
    scopes: Vec<Scope>,
}

impl TwitchProvider {
    pub fn new(client_id: &str, client_secret: &str, redirect_url: &str) -> Result<Self> {
        let client = create_oauth_client(
            client_id,
            client_secret,
            "https://id.twitch.tv/oauth2/authorize",
            "https://id.twitch.tv/oauth2/token",
            redirect_url,
        )?;

        Ok(Self {
            client,
            scopes: vec![
                Scope::new("user:read:email".to_string()),
                Scope::new("openid".to_string()),
            ],
        })
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes.into_iter().map(Scope::new).collect();
        self
    }
}

#[derive(Debug, Deserialize)]
struct TwitchUserResponse {
    data: Vec<TwitchUserInfo>,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TwitchUserInfo {
    id: String,
    login: String,
    display_name: Option<String>,
    email: Option<String>,
    profile_image_url: Option<String>,
}

#[async_trait]
impl OAuthProvider for TwitchProvider {
    fn name(&self) -> &'static str {
        "twitch"
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
            .get("https://api.twitch.tv/helix/users")
            .bearer_auth(access_token)
            .header("Client-Id", self.client().client_id().as_str())
            .send()
            .await
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        if !response.status().is_success() {
            return Err(TsaError::Internal(format!(
                "Failed to get user info: {}",
                response.status()
            )));
        }

        let user_response: TwitchUserResponse = response
            .json()
            .await
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        let user = user_response
            .data
            .into_iter()
            .next()
            .ok_or_else(|| TsaError::Internal("No user data in response".to_string()))?;

        Ok(OAuthUserInfo {
            provider_user_id: user.id,
            email: user.email,
            email_verified: Some(true),
            name: user.display_name,
            image: user.profile_image_url,
        })
    }
}
