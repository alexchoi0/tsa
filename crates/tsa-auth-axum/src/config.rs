use serde::Deserialize;
use std::env;

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    pub app_name: String,
    pub jwt_secret: String,
    pub session_secret: String,
    pub cors_origins: Vec<String>,
    pub oauth_providers: OAuthConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct OAuthConfig {
    pub google: Option<OAuthProviderConfig>,
    pub github: Option<OAuthProviderConfig>,
    pub discord: Option<OAuthProviderConfig>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct OAuthProviderConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_url: String,
}

impl ServerConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let host = env::var("TSA_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("TSA_PORT")
            .unwrap_or_else(|_| "3000".to_string())
            .parse()?;
        let app_name = env::var("TSA_APP_NAME").unwrap_or_else(|_| "TSA".to_string());
        let jwt_secret = env::var("TSA_JWT_SECRET")
            .unwrap_or_else(|_| "change-me-in-production-jwt-secret".to_string());
        let session_secret = env::var("TSA_SESSION_SECRET")
            .unwrap_or_else(|_| "change-me-in-production-session-secret".to_string());

        let cors_origins = env::var("TSA_CORS_ORIGINS")
            .unwrap_or_else(|_| "http://localhost:3000".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .collect();

        let oauth_providers = OAuthConfig {
            google: Self::parse_oauth_provider("GOOGLE"),
            github: Self::parse_oauth_provider("GITHUB"),
            discord: Self::parse_oauth_provider("DISCORD"),
        };

        Ok(Self {
            host,
            port,
            app_name,
            jwt_secret,
            session_secret,
            cors_origins,
            oauth_providers,
        })
    }

    fn parse_oauth_provider(name: &str) -> Option<OAuthProviderConfig> {
        let client_id = env::var(format!("TSA_{}_CLIENT_ID", name)).ok()?;
        let client_secret = env::var(format!("TSA_{}_CLIENT_SECRET", name)).ok()?;
        let redirect_url = env::var(format!("TSA_{}_REDIRECT_URL", name)).ok()?;

        Some(OAuthProviderConfig {
            client_id,
            client_secret,
            redirect_url,
        })
    }
}
