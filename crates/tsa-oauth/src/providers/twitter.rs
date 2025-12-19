use async_trait::async_trait;
use oauth2::Scope;
use serde::Deserialize;
use tsa_core::{Result, TsaError};

use crate::{create_oauth_client, ConfiguredClient, OAuthProvider, OAuthUserInfo};

pub struct TwitterProvider {
    client: ConfiguredClient,
    scopes: Vec<Scope>,
}

impl TwitterProvider {
    pub fn new(client_id: &str, client_secret: &str, redirect_url: &str) -> Result<Self> {
        let client = create_oauth_client(
            client_id,
            client_secret,
            "https://twitter.com/i/oauth2/authorize",
            "https://api.twitter.com/2/oauth2/token",
            redirect_url,
        )?;

        Ok(Self {
            client,
            scopes: vec![
                Scope::new("tweet.read".to_string()),
                Scope::new("users.read".to_string()),
            ],
        })
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes.into_iter().map(Scope::new).collect();
        self
    }
}

#[derive(Debug, Deserialize)]
struct TwitterUserResponse {
    data: TwitterUserInfo,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct TwitterUserInfo {
    id: String,
    name: Option<String>,
    username: String,
    profile_image_url: Option<String>,
}

#[async_trait]
impl OAuthProvider for TwitterProvider {
    fn name(&self) -> &'static str {
        "twitter"
    }

    fn client(&self) -> &ConfiguredClient {
        &self.client
    }

    fn scopes(&self) -> Vec<Scope> {
        self.scopes.clone()
    }

    fn use_pkce(&self) -> bool {
        true
    }

    async fn get_user_info(&self, access_token: &str) -> Result<OAuthUserInfo> {
        let client = reqwest::Client::new();
        let response = client
            .get("https://api.twitter.com/2/users/me")
            .query(&[("user.fields", "profile_image_url")])
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

        let user_response: TwitterUserResponse = response
            .json()
            .await
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        Ok(OAuthUserInfo {
            provider_user_id: user_response.data.id,
            email: None,
            email_verified: None,
            name: user_response.data.name,
            image: user_response.data.profile_image_url,
        })
    }
}
