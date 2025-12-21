use async_trait::async_trait;
use oauth2::Scope;
use serde::Deserialize;
use tsa_auth_core::{Result, TsaError};

use crate::{create_oauth_client, ConfiguredClient, OAuthProvider, OAuthUserInfo};

pub struct SlackProvider {
    client: ConfiguredClient,
    scopes: Vec<Scope>,
}

impl SlackProvider {
    pub fn new(client_id: &str, client_secret: &str, redirect_url: &str) -> Result<Self> {
        let client = create_oauth_client(
            client_id,
            client_secret,
            "https://slack.com/openid/connect/authorize",
            "https://slack.com/api/openid.connect.token",
            redirect_url,
        )?;

        Ok(Self {
            client,
            scopes: vec![
                Scope::new("openid".to_string()),
                Scope::new("email".to_string()),
                Scope::new("profile".to_string()),
            ],
        })
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes.into_iter().map(Scope::new).collect();
        self
    }
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SlackUserInfo {
    ok: bool,
    sub: String,
    email: Option<String>,
    email_verified: Option<bool>,
    name: Option<String>,
    picture: Option<String>,
}

#[async_trait]
impl OAuthProvider for SlackProvider {
    fn name(&self) -> &'static str {
        "slack"
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
            .get("https://slack.com/api/openid.connect.userInfo")
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

        let user_info: SlackUserInfo = response
            .json()
            .await
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        if !user_info.ok {
            return Err(TsaError::Internal("Slack API returned error".to_string()));
        }

        Ok(OAuthUserInfo {
            provider_user_id: user_info.sub,
            email: user_info.email,
            email_verified: user_info.email_verified,
            name: user_info.name,
            image: user_info.picture,
        })
    }
}
