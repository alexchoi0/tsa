use std::sync::Arc;
use tsa::{Auth, AuthConfig, NoopCallbacks};
use tsa_adapter::InMemoryAdapter;

use crate::config::ServerConfig;

pub type AuthInstance = Auth<InMemoryAdapter, NoopCallbacks>;

pub struct AppState {
    pub config: ServerConfig,
    pub auth: AuthInstance,
}

impl AppState {
    pub async fn new(config: ServerConfig) -> anyhow::Result<Self> {
        let adapter = InMemoryAdapter::new();
        let auth_config = AuthConfig::new().app_name(&config.app_name);
        let auth = Auth::new(adapter, auth_config, NoopCallbacks);

        Ok(Self { config, auth })
    }
}

pub type SharedState = Arc<AppState>;
