use std::env;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct GrpcConfig {
    pub host: String,
    pub port: u16,
    pub app_name: String,
    pub jwt_secret: String,
    pub session_secret: String,
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
}

impl GrpcConfig {
    pub fn from_env() -> anyhow::Result<Self> {
        let host = env::var("TSA_HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = env::var("TSA_PORT")
            .unwrap_or_else(|_| "50051".to_string())
            .parse()?;
        let app_name = env::var("TSA_APP_NAME").unwrap_or_else(|_| "TSA".to_string());
        let jwt_secret = env::var("TSA_JWT_SECRET")
            .unwrap_or_else(|_| "change-me-in-production-jwt-secret".to_string());
        let session_secret = env::var("TSA_SESSION_SECRET")
            .unwrap_or_else(|_| "change-me-in-production-session-secret".to_string());

        let tls_cert = env::var("TSA_TLS_CERT").ok().map(PathBuf::from);
        let tls_key = env::var("TSA_TLS_KEY").ok().map(PathBuf::from);

        Ok(Self {
            host,
            port,
            app_name,
            jwt_secret,
            session_secret,
            tls_cert,
            tls_key,
        })
    }

    pub fn tls_enabled(&self) -> bool {
        self.tls_cert.is_some() && self.tls_key.is_some()
    }
}
