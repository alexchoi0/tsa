use async_trait::async_trait;
use oauth2::Scope;
use serde::Deserialize;
use tsa_core::{Result, TsaError};

use crate::{create_oauth_client, ConfiguredClient, OAuthProvider, OAuthUserInfo};

pub struct GitHubProvider {
    client: ConfiguredClient,
    scopes: Vec<Scope>,
}

impl GitHubProvider {
    pub fn new(client_id: &str, client_secret: &str, redirect_url: &str) -> Result<Self> {
        let client = create_oauth_client(
            client_id,
            client_secret,
            "https://github.com/login/oauth/authorize",
            "https://github.com/login/oauth/access_token",
            redirect_url,
        )?;

        Ok(Self {
            client,
            scopes: vec![
                Scope::new("read:user".to_string()),
                Scope::new("user:email".to_string()),
            ],
        })
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes.into_iter().map(Scope::new).collect();
        self
    }
}

#[derive(Debug, Deserialize)]
struct GitHubUser {
    id: i64,
    email: Option<String>,
    name: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Debug, Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

#[async_trait]
impl OAuthProvider for GitHubProvider {
    fn name(&self) -> &'static str {
        "github"
    }

    fn client(&self) -> &ConfiguredClient {
        &self.client
    }

    fn scopes(&self) -> Vec<Scope> {
        self.scopes.clone()
    }

    fn use_pkce(&self) -> bool {
        false
    }

    async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo> {
        let client = reqwest::Client::new();

        let user_response = client
            .get("https://api.github.com/user")
            .header("User-Agent", "tsa-auth")
            .bearer_auth(access_token)
            .send()
            .await
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        if !user_response.status().is_success() {
            return Err(TsaError::Internal(format!(
                "Failed to get user info: {}",
                user_response.status()
            )));
        }

        let user: GitHubUser = user_response
            .json()
            .await
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        let (email, email_verified) = if user.email.is_some() {
            (user.email, Some(true))
        } else {
            let emails_response = client
                .get("https://api.github.com/user/emails")
                .header("User-Agent", "tsa-auth")
                .bearer_auth(access_token)
                .send()
                .await
                .map_err(|e| TsaError::Internal(e.to_string()))?;

            if emails_response.status().is_success() {
                let emails: Vec<GitHubEmail> = emails_response
                    .json()
                    .await
                    .map_err(|e| TsaError::Internal(e.to_string()))?;

                let primary_email = emails.into_iter().find(|e| e.primary && e.verified);

                match primary_email {
                    Some(e) => (Some(e.email), Some(e.verified)),
                    None => (None, None),
                }
            } else {
                (None, None)
            }
        };

        Ok(OAuthUserInfo {
            provider_user_id: user.id.to_string(),
            email,
            email_verified,
            name: user.name,
            image: user.avatar_url,
        })
    }
}
