use std::net::SocketAddr;
use std::sync::Arc;

use tonic::transport::{Identity, Server, ServerTlsConfig};
use tracing::{info, warn};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use tsa_auth_grpc::{
    config::GrpcConfig,
    services::{
        ApiKeyServiceImpl, AuthServiceImpl, HealthServiceImpl, OrganizationServiceImpl,
        SessionServiceImpl, UserServiceImpl,
    },
    state::AppState,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "tsa_auth_grpc=info,tonic=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let config = GrpcConfig::from_env()?;
    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;

    let state = Arc::new(AppState::new(config.clone()).await?);

    let health_service = HealthServiceImpl::new().into_server();
    let auth_service = AuthServiceImpl::new(state.clone()).into_server();
    let user_service = UserServiceImpl::new(state.clone()).into_server();
    let session_service = SessionServiceImpl::new(state.clone()).into_server();
    let org_service = OrganizationServiceImpl::new(state.clone()).into_server();
    let apikey_service = ApiKeyServiceImpl::new(state.clone()).into_server();

    let mut server = Server::builder();

    if config.tls_enabled() {
        info!("Loading TLS certificates...");
        let cert_pem = std::fs::read_to_string(config.tls_cert.as_ref().unwrap())?;
        let key_pem = std::fs::read_to_string(config.tls_key.as_ref().unwrap())?;

        let identity = Identity::from_pem(cert_pem, key_pem);
        let tls_config = ServerTlsConfig::new().identity(identity);

        info!("Starting gRPC server with TLS on {}", addr);
        server
            .tls_config(tls_config)?
            .add_service(health_service)
            .add_service(auth_service)
            .add_service(user_service)
            .add_service(session_service)
            .add_service(org_service)
            .add_service(apikey_service)
            .serve(addr)
            .await?;
    } else {
        warn!(
            "Starting gRPC server WITHOUT TLS on {} (insecure mode)",
            addr
        );
        server
            .add_service(health_service)
            .add_service(auth_service)
            .add_service(user_service)
            .add_service(session_service)
            .add_service(org_service)
            .add_service(apikey_service)
            .serve(addr)
            .await?;
    }

    Ok(())
}
