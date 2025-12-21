use async_trait::async_trait;
use oauth2::Scope;
use serde::Deserialize;
use tsa_auth_core::{Result, TsaError};

use crate::{create_oauth_client, ConfiguredClient, OAuthProvider, OAuthUserInfo};

pub struct MicrosoftProvider {
    client: ConfiguredClient,
    scopes: Vec<Scope>,
}

impl MicrosoftProvider {
    pub fn new(client_id: &str, client_secret: &str, redirect_url: &str) -> Result<Self> {
        Self::with_tenant(client_id, client_secret, redirect_url, "common")
    }

    pub fn with_tenant(
        client_id: &str,
        client_secret: &str,
        redirect_url: &str,
        tenant: &str,
    ) -> Result<Self> {
        let client = create_oauth_client(
            client_id,
            client_secret,
            &format!("https://login.microsoftonline.com/{}/oauth2/v2.0/authorize", tenant),
            &format!("https://login.microsoftonline.com/{}/oauth2/v2.0/token", tenant),
            redirect_url,
        )?;

        Ok(Self {
            client,
            scopes: vec![
                Scope::new("openid".to_string()),
                Scope::new("email".to_string()),
                Scope::new("profile".to_string()),
                Scope::new("User.Read".to_string()),
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
struct MicrosoftUserInfo {
    id: String,
    #[serde(rename = "displayName")]
    display_name: Option<String>,
    mail: Option<String>,
    #[serde(rename = "userPrincipalName")]
    user_principal_name: Option<String>,
}

#[async_trait]
impl OAuthProvider for MicrosoftProvider {
    fn name(&self) -> &'static str {
        "microsoft"
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
            .get("https://graph.microsoft.com/v1.0/me")
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

        let user_info: MicrosoftUserInfo = response
            .json()
            .await
            .map_err(|e| TsaError::Internal(e.to_string()))?;

        let email = user_info.mail.or(user_info.user_principal_name);

        Ok(OAuthUserInfo {
            provider_user_id: user_info.id,
            email,
            email_verified: Some(true),
            name: user_info.display_name,
            image: None,
        })
    }
}
