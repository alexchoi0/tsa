use tonic::{Request, Response, Status};
use tsa_auth_proto::{HealthCheckRequest, HealthCheckResponse, HealthService, HealthServiceServer};

pub struct HealthServiceImpl;

impl Default for HealthServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl HealthServiceImpl {
    pub fn new() -> Self {
        Self
    }

    pub fn into_server(self) -> HealthServiceServer<Self> {
        HealthServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl HealthService for HealthServiceImpl {
    async fn check(
        &self,
        _request: Request<HealthCheckRequest>,
    ) -> Result<Response<HealthCheckResponse>, Status> {
        Ok(Response::new(HealthCheckResponse {
            status: "healthy".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        }))
    }
}
