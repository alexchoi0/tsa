use anyhow::{anyhow, Result};
use tonic::metadata::MetadataValue;
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Request, Status};

use tsa_auth_proto::{
    ApiKeyServiceClient, AuthServiceClient, HealthServiceClient, OrganizationServiceClient,
    SessionServiceClient, UserServiceClient,
};

pub struct TsaClient {
    endpoint: String,
    token: Option<String>,
    insecure: bool,
}

impl TsaClient {
    pub fn new(endpoint: &str, token: Option<&str>, insecure: bool) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            token: token.map(|t| t.to_string()),
            insecure,
        }
    }

    async fn create_channel(&self) -> Result<Channel> {
        let endpoint =
            if self.endpoint.starts_with("http://") || self.endpoint.starts_with("https://") {
                self.endpoint.clone()
            } else {
                format!("http://{}", self.endpoint)
            };

        let mut ep = Endpoint::from_shared(endpoint.clone())?;

        if endpoint.starts_with("https://") && !self.insecure {
            let tls = ClientTlsConfig::new();
            ep = ep.tls_config(tls)?;
        }

        let channel = ep
            .connect()
            .await
            .map_err(|e| anyhow!("Failed to connect to {}: {}", self.endpoint, e))?;

        Ok(channel)
    }

    fn add_auth<T>(&self, request: &mut Request<T>) {
        if let Some(ref token) = self.token {
            if let Ok(val) = format!("Bearer {}", token).parse::<MetadataValue<_>>() {
                request.metadata_mut().insert("authorization", val);
            }
        }
    }

    pub async fn auth_client(&self) -> Result<AuthServiceClient<Channel>> {
        let channel = self.create_channel().await?;
        Ok(AuthServiceClient::new(channel))
    }

    pub async fn user_client(&self) -> Result<UserServiceClient<Channel>> {
        let channel = self.create_channel().await?;
        Ok(UserServiceClient::new(channel))
    }

    pub async fn session_client(&self) -> Result<SessionServiceClient<Channel>> {
        let channel = self.create_channel().await?;
        Ok(SessionServiceClient::new(channel))
    }

    pub async fn org_client(&self) -> Result<OrganizationServiceClient<Channel>> {
        let channel = self.create_channel().await?;
        Ok(OrganizationServiceClient::new(channel))
    }

    pub async fn apikey_client(&self) -> Result<ApiKeyServiceClient<Channel>> {
        let channel = self.create_channel().await?;
        Ok(ApiKeyServiceClient::new(channel))
    }

    pub async fn health_client(&self) -> Result<HealthServiceClient<Channel>> {
        let channel = self.create_channel().await?;
        Ok(HealthServiceClient::new(channel))
    }

    #[allow(dead_code)]
    pub fn token(&self) -> Option<&str> {
        self.token.as_deref()
    }

    pub fn auth_request<T>(&self, inner: T) -> Request<T> {
        let mut request = Request::new(inner);
        self.add_auth(&mut request);
        request
    }
}

pub fn status_to_error(status: Status) -> anyhow::Error {
    anyhow!("{}", status.message())
}
