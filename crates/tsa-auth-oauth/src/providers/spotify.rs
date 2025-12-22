use async_trait::async_trait;
use oauth2::Scope;
use serde::Deserialize;
use tsa_auth_core::{Result, TsaError};

use crate::{create_oauth_client, ConfiguredClient, OAuthProvider, OAuthUserInfo};

pub struct SpotifyProvider {
    client: ConfiguredClient,
    scopes: Vec<Scope>,
}

impl SpotifyProvider {
    pub fn new(client_id: &str, client_secret: &str, redirect_url: &str) -> Result<Self> {
        let client = create_oauth_client(
            client_id,
            client_secret,
            "https://accounts.spotify.com/authorize",
            "https://accounts.spotify.com/api/token",
            redirect_url,
        )?;

        Ok(Self {
            client,
            scopes: vec![
                Scope::new("user-read-email".to_string()),
                Scope::new("user-read-private".to_string()),
            ],
        })
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes.into_iter().map(Scope::new).collect();
        self
    }
}

#[derive(Debug, Deserialize)]
struct SpotifyImage {
    url: String,
}

#[allow(dead_code)]
#[derive(Debug, Deserialize)]
struct SpotifyUserInfo {
    id: String,
    email: Option<String>,
    display_name: Option<String>,
    images: Option<Vec<SpotifyImage>>,
}

#[async_trait]
impl OAuthProvider for SpotifyProvider {
    fn name(&self) -> &'static str {
        "spotify"
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
            .get("https://api.spotify.com/v1/me")
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

        let user_info: SpotifyUserInfo = response
            .json()
            .await
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        let image = user_info
            .images
            .and_then(|imgs| imgs.into_iter().next().map(|i| i.url));

        Ok(OAuthUserInfo {
            provider_user_id: user_info.id,
            email: user_info.email,
            email_verified: Some(true),
            name: user_info.display_name,
            image,
        })
    }
}
