use async_trait::async_trait;
use oauth2::Scope;
use serde::Deserialize;
use tsa_core::{Result, TsaError};

use crate::{create_oauth_client, ConfiguredClient, OAuthProvider, OAuthUserInfo};

pub struct AppleProvider {
    client: ConfiguredClient,
    scopes: Vec<Scope>,
}

impl AppleProvider {
    pub fn new(client_id: &str, client_secret: &str, redirect_url: &str) -> Result<Self> {
        let client = create_oauth_client(
            client_id,
            client_secret,
            "https://appleid.apple.com/auth/authorize",
            "https://appleid.apple.com/auth/token",
            redirect_url,
        )?;

        Ok(Self {
            client,
            scopes: vec![
                Scope::new("name".to_string()),
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
struct AppleIdToken {
    sub: String,
    email: Option<String>,
    email_verified: Option<String>,
}

#[async_trait]
impl OAuthProvider for AppleProvider {
    fn name(&self) -> &'static str {
        "apple"
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
        let parts: Vec<&str> = access_token.split('.').collect();
        if parts.len() != 3 {
            return Err(TsaError::Internal("Invalid Apple ID token format".to_string()));
        }

        let payload = base64::Engine::decode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            parts[1],
        )
        .map_err(|e| TsaError::Internal(format!("Failed to decode token: {}", e)))?;

        let token_data: AppleIdToken = serde_json::from_slice(&payload)
            .map_err(|e| TsaError::Internal(format!("Failed to parse token: {}", e)))?;

        Ok(OAuthUserInfo {
            provider_user_id: token_data.sub,
            email: token_data.email,
            email_verified: token_data.email_verified.map(|v| v == "true"),
            name: None,
            image: None,
        })
    }
}
