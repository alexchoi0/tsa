use std::sync::Arc;
use tsa_auth::{Auth, AuthConfig, NoopCallbacks};
use tsa_auth_adapter::InMemoryAdapter;

use crate::config::GrpcConfig;

pub type AuthInstance = Auth<InMemoryAdapter, NoopCallbacks>;

pub struct AppState {
    pub config: GrpcConfig,
    pub auth: AuthInstance,
}

impl AppState {
    pub async fn new(config: GrpcConfig) -> anyhow::Result<Self> {
        let adapter = InMemoryAdapter::new();
        let auth_config = AuthConfig::new().app_name(&config.app_name);
        let auth = Auth::new(adapter, auth_config, NoopCallbacks);

        Ok(Self { config, auth })
    }
}

pub type SharedState = Arc<AppState>;
