use async_trait::async_trait;
use oauth2::Scope;
use serde::Deserialize;
use tsa_core::{Result, TsaError};

use crate::{create_oauth_client, ConfiguredClient, OAuthProvider, OAuthUserInfo};

pub struct FacebookProvider {
    client: ConfiguredClient,
    scopes: Vec<Scope>,
}

impl FacebookProvider {
    pub fn new(client_id: &str, client_secret: &str, redirect_url: &str) -> Result<Self> {
        let client = create_oauth_client(
            client_id,
            client_secret,
            "https://www.facebook.com/v18.0/dialog/oauth",
            "https://graph.facebook.com/v18.0/oauth/access_token",
            redirect_url,
        )?;

        Ok(Self {
            client,
            scopes: vec![
                Scope::new("email".to_string()),
                Scope::new("public_profile".to_string()),
            ],
        })
    }

    pub fn with_scopes(mut self, scopes: Vec<String>) -> Self {
        self.scopes = scopes.into_iter().map(Scope::new).collect();
        self
    }
}

#[derive(Debug, Deserialize)]
struct FacebookPicture {
    data: FacebookPictureData,
}

#[derive(Debug, Deserialize)]
struct FacebookPictureData {
    url: String,
}

#[derive(Debug, Deserialize)]
struct FacebookUserInfo {
    id: String,
    email: Option<String>,
    name: Option<String>,
    picture: Option<FacebookPicture>,
}

#[async_trait]
impl OAuthProvider for FacebookProvider {
    fn name(&self) -> &'static str {
        "facebook"
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
            .get("https://graph.facebook.com/me")
            .query(&[("fields", "id,name,email,picture.type(large)")])
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

        let user_info: FacebookUserInfo = response
            .json()
            .await
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        Ok(OAuthUserInfo {
            provider_user_id: user_info.id,
            email: user_info.email,
            email_verified: Some(true),
            name: user_info.name,
            image: user_info.picture.map(|p| p.data.url),
        })
    }
}
