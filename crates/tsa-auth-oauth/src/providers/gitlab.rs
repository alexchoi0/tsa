use async_trait::async_trait;
use oauth2::Scope;
use serde::Deserialize;
use tsa_auth_core::{Result, TsaError};

use crate::{create_oauth_client, ConfiguredClient, OAuthProvider, OAuthUserInfo};

pub struct GitLabProvider {
    client: ConfiguredClient,
    scopes: Vec<Scope>,
    base_url: String,
}

impl GitLabProvider {
    pub fn new(client_id: &str, client_secret: &str, redirect_url: &str) -> Result<Self> {
        Self::with_base_url(client_id, client_secret, redirect_url, "https://gitlab.com")
    }

    pub fn with_base_url(
        client_id: &str,
        client_secret: &str,
        redirect_url: &str,
        base_url: &str,
    ) -> Result<Self> {
        let client = create_oauth_client(
            client_id,
            client_secret,
            &format!("{}/oauth/authorize", base_url),
            &format!("{}/oauth/token", base_url),
            redirect_url,
        )?;

        Ok(Self {
            client,
            scopes: vec![
                Scope::new("read_user".to_string()),
                Scope::new("openid".to_string()),
                Scope::new("email".to_string()),
            ],
            base_url: base_url.to_string(),
        })
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes.into_iter().map(Scope::new).collect();
        self
    }
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct GitLabUserInfo {
    id: i64,
    email: Option<String>,
    name: Option<String>,
    username: String,
    avatar_url: Option<String>,
    confirmed_at: Option<String>,
}

#[async_trait]
impl OAuthProvider for GitLabProvider {
    fn name(&self) -> &'static str {
        "gitlab"
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
            .get(format!("{}/api/v4/user", self.base_url))
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

        let user_info: GitLabUserInfo = response
            .json()
            .await
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        Ok(OAuthUserInfo {
            provider_user_id: user_info.id.to_string(),
            email: user_info.email,
            email_verified: user_info.confirmed_at.map(|_| true),
            name: user_info.name,
            image: user_info.avatar_url,
        })
    }
}
