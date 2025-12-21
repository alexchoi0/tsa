use std::collections::HashMap;
use std::sync::Arc;

use oauth2::{CsrfToken, PkceCodeChallenge};
use tsa_auth_core::{Result, TsaError};

use crate::provider::{OAuthProvider, OAuthTokens, OAuthUserInfo};
use crate::providers::{
    AppleProvider, DiscordProvider, FacebookProvider, GitHubProvider, GitLabProvider,
    GoogleProvider, LinkedInProvider, MicrosoftProvider, SlackProvider, SpotifyProvider,
    TwitchProvider, TwitterProvider,
};
use crate::state::OAuthState;

pub struct ProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
    pub scopes: Option<Vec<String>>,
}

pub struct OAuthRegistry {
    providers: HashMap<String, Arc<dyn OAuthProvider>>,
    secret: String,
}

impl OAuthRegistry {
    pub fn new(secret: impl Into<String>) -> Self {
        Self {
            providers: HashMap::new(),
            secret: secret.into(),
        }
    }

    pub fn register<P: OAuthProvider + 'static>(&mut self, provider: P) {
        self.providers
            .insert(provider.name().to_string(), Arc::new(provider));
    }

    pub fn register_google(&mut self, config: ProviderConfig) -> Result<()> {
        let mut provider = GoogleProvider::new(
            &config.client_id,
            &config.client_secret,
            &config.redirect_url,
        )?;
        if let Some(scopes) = config.scopes {
            provider = provider.with_scopes(scopes);
        }
        self.register(provider);
        Ok(())
    }

    pub fn register_github(&mut self, config: ProviderConfig) -> Result<()> {
        let mut provider = GitHubProvider::new(
            &config.client_id,
            &config.client_secret,
            &config.redirect_url,
        )?;
        if let Some(scopes) = config.scopes {
            provider = provider.with_scopes(scopes);
        }
        self.register(provider);
        Ok(())
    }

    pub fn register_discord(&mut self, config: ProviderConfig) -> Result<()> {
        let mut provider = DiscordProvider::new(
            &config.client_id,
            &config.client_secret,
            &config.redirect_url,
        )?;
        if let Some(scopes) = config.scopes {
            provider = provider.with_scopes(scopes);
        }
        self.register(provider);
        Ok(())
    }

    pub fn register_apple(&mut self, config: ProviderConfig) -> Result<()> {
        let mut provider = AppleProvider::new(
            &config.client_id,
            &config.client_secret,
            &config.redirect_url,
        )?;
        if let Some(scopes) = config.scopes {
            provider = provider.with_scopes(scopes);
        }
        self.register(provider);
        Ok(())
    }

    pub fn register_microsoft(&mut self, config: ProviderConfig) -> Result<()> {
        let mut provider = MicrosoftProvider::new(
            &config.client_id,
            &config.client_secret,
            &config.redirect_url,
        )?;
        if let Some(scopes) = config.scopes {
            provider = provider.with_scopes(scopes);
        }
        self.register(provider);
        Ok(())
    }

    pub fn register_gitlab(&mut self, config: ProviderConfig) -> Result<()> {
        let mut provider = GitLabProvider::new(
            &config.client_id,
            &config.client_secret,
            &config.redirect_url,
        )?;
        if let Some(scopes) = config.scopes {
            provider = provider.with_scopes(scopes);
        }
        self.register(provider);
        Ok(())
    }

    pub fn register_twitter(&mut self, config: ProviderConfig) -> Result<()> {
        let mut provider = TwitterProvider::new(
            &config.client_id,
            &config.client_secret,
            &config.redirect_url,
        )?;
        if let Some(scopes) = config.scopes {
            provider = provider.with_scopes(scopes);
        }
        self.register(provider);
        Ok(())
    }

    pub fn register_facebook(&mut self, config: ProviderConfig) -> Result<()> {
        let mut provider = FacebookProvider::new(
            &config.client_id,
            &config.client_secret,
            &config.redirect_url,
        )?;
        if let Some(scopes) = config.scopes {
            provider = provider.with_scopes(scopes);
        }
        self.register(provider);
        Ok(())
    }

    pub fn register_linkedin(&mut self, config: ProviderConfig) -> Result<()> {
        let mut provider = LinkedInProvider::new(
            &config.client_id,
            &config.client_secret,
            &config.redirect_url,
        )?;
        if let Some(scopes) = config.scopes {
            provider = provider.with_scopes(scopes);
        }
        self.register(provider);
        Ok(())
    }

    pub fn register_spotify(&mut self, config: ProviderConfig) -> Result<()> {
        let mut provider = SpotifyProvider::new(
            &config.client_id,
            &config.client_secret,
            &config.redirect_url,
        )?;
        if let Some(scopes) = config.scopes {
            provider = provider.with_scopes(scopes);
        }
        self.register(provider);
        Ok(())
    }

    pub fn register_slack(&mut self, config: ProviderConfig) -> Result<()> {
        let mut provider = SlackProvider::new(
            &config.client_id,
            &config.client_secret,
            &config.redirect_url,
        )?;
        if let Some(scopes) = config.scopes {
            provider = provider.with_scopes(scopes);
        }
        self.register(provider);
        Ok(())
    }

    pub fn register_twitch(&mut self, config: ProviderConfig) -> Result<()> {
        let mut provider = TwitchProvider::new(
            &config.client_id,
            &config.client_secret,
            &config.redirect_url,
        )?;
        if let Some(scopes) = config.scopes {
            provider = provider.with_scopes(scopes);
        }
        self.register(provider);
        Ok(())
    }

    pub fn get(&self, name: &str) -> Option<Arc<dyn OAuthProvider>> {
        self.providers.get(name).cloned()
    }

    pub fn authorization_url(&self, provider_name: &str) -> Result<(String, String)> {
        let provider = self.providers.get(provider_name).ok_or_else(|| {
            TsaError::Configuration(format!("Unknown provider: {}", provider_name))
        })?;

        let client = provider.client();
        let csrf_token = CsrfToken::new_random();

        let (url, pkce_verifier) = if provider.use_pkce() {
            let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

            let mut builder = client
                .authorize_url(|| csrf_token.clone())
                .set_pkce_challenge(pkce_challenge);

            for scope in provider.scopes() {
                builder = builder.add_scope(scope);
            }

            let (url, _) = builder.url();
            (url.to_string(), Some(pkce_verifier.secret().clone()))
        } else {
            let mut builder = client.authorize_url(|| csrf_token.clone());

            for scope in provider.scopes() {
                builder = builder.add_scope(scope);
            }

            let (url, _) = builder.url();
            (url.to_string(), None)
        };

        let state = OAuthState::new(
            provider_name,
            csrf_token.secret().clone(),
            pkce_verifier,
            &self.secret,
        );

        Ok((url, state.encode()?))
    }

    pub async fn exchange_code(
        &self,
        provider_name: &str,
        code: &str,
        state: &str,
    ) -> Result<(OAuthTokens, OAuthUserInfo)> {
        let decoded_state = OAuthState::decode(state, &self.secret)?;

        if decoded_state.provider != provider_name {
            return Err(TsaError::InvalidToken);
        }

        let provider = self.providers.get(provider_name).ok_or_else(|| {
            TsaError::Configuration(format!("Unknown provider: {}", provider_name))
        })?;

        let tokens = provider
            .exchange_code(code, decoded_state.pkce_verifier.as_deref())
            .await?;

        let user_info = provider.get_user_info(&tokens.access_token).await?;

        Ok((tokens, user_info))
    }

    pub fn providers(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> ProviderConfig {
        ProviderConfig {
            client_id: "test_client_id".to_string(),
            client_secret: "test_client_secret".to_string(),
            redirect_url: "https://example.com/callback".to_string(),
            scopes: None,
        }
    }

    #[test]
    fn test_registry_new() {
        let registry = OAuthRegistry::new("my_secret");
        assert!(registry.providers().is_empty());
    }

    #[test]
    fn test_register_google() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_google(test_config()).unwrap();

        assert!(registry.get("google").is_some());
        assert!(registry.providers().contains(&"google"));
    }

    #[test]
    fn test_register_github() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_github(test_config()).unwrap();

        assert!(registry.get("github").is_some());
    }

    #[test]
    fn test_register_discord() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_discord(test_config()).unwrap();

        assert!(registry.get("discord").is_some());
    }

    #[test]
    fn test_register_apple() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_apple(test_config()).unwrap();

        assert!(registry.get("apple").is_some());
    }

    #[test]
    fn test_register_microsoft() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_microsoft(test_config()).unwrap();

        assert!(registry.get("microsoft").is_some());
    }

    #[test]
    fn test_register_gitlab() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_gitlab(test_config()).unwrap();

        assert!(registry.get("gitlab").is_some());
    }

    #[test]
    fn test_register_twitter() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_twitter(test_config()).unwrap();

        assert!(registry.get("twitter").is_some());
    }

    #[test]
    fn test_register_facebook() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_facebook(test_config()).unwrap();

        assert!(registry.get("facebook").is_some());
    }

    #[test]
    fn test_register_linkedin() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_linkedin(test_config()).unwrap();

        assert!(registry.get("linkedin").is_some());
    }

    #[test]
    fn test_register_spotify() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_spotify(test_config()).unwrap();

        assert!(registry.get("spotify").is_some());
    }

    #[test]
    fn test_register_slack() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_slack(test_config()).unwrap();

        assert!(registry.get("slack").is_some());
    }

    #[test]
    fn test_register_twitch() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_twitch(test_config()).unwrap();

        assert!(registry.get("twitch").is_some());
    }

    #[test]
    fn test_register_multiple_providers() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_google(test_config()).unwrap();
        registry.register_github(test_config()).unwrap();
        registry.register_discord(test_config()).unwrap();

        let providers = registry.providers();
        assert_eq!(providers.len(), 3);
        assert!(providers.contains(&"google"));
        assert!(providers.contains(&"github"));
        assert!(providers.contains(&"discord"));
    }

    #[test]
    fn test_get_unknown_provider() {
        let registry = OAuthRegistry::new("secret");
        assert!(registry.get("unknown").is_none());
    }

    #[test]
    fn test_authorization_url_unknown_provider() {
        let registry = OAuthRegistry::new("secret");
        let result = registry.authorization_url("unknown");
        assert!(result.is_err());
    }

    #[test]
    fn test_authorization_url_generates_state() {
        let mut registry = OAuthRegistry::new("secret");
        registry.register_google(test_config()).unwrap();

        let (url, state) = registry.authorization_url("google").unwrap();

        assert!(url.contains("accounts.google.com"));
        assert!(!state.is_empty());
    }

    #[test]
    fn test_register_with_custom_scopes() {
        let config = ProviderConfig {
            client_id: "id".to_string(),
            client_secret: "secret".to_string(),
            redirect_url: "https://example.com/callback".to_string(),
            scopes: Some(vec!["custom:scope".to_string()]),
        };

        let mut registry = OAuthRegistry::new("secret");
        registry.register_google(config).unwrap();

        assert!(registry.get("google").is_some());
    }

    #[test]
    fn test_provider_config_fields() {
        let config = ProviderConfig {
            client_id: "my_client".to_string(),
            client_secret: "my_secret".to_string(),
            redirect_url: "https://app.com/auth/callback".to_string(),
            scopes: Some(vec!["email".to_string(), "profile".to_string()]),
        };

        assert_eq!(config.client_id, "my_client");
        assert_eq!(config.client_secret, "my_secret");
        assert_eq!(config.redirect_url, "https://app.com/auth/callback");
        assert_eq!(
            config.scopes,
            Some(vec!["email".to_string(), "profile".to_string()])
        );
    }
}
