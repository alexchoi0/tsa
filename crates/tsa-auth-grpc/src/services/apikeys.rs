use tonic::{Request, Response, Status};
use tsa_auth_proto::{
    ApiKeyResponse, ApiKeyService, ApiKeyServiceServer, CreateApiKeyRequest, CreateApiKeyResponse,
    DeleteApiKeyRequest, ListApiKeysRequest, ListApiKeysResponse, MessageResponse,
    UpdateApiKeyRequest,
};
use uuid::Uuid;

use crate::error::to_status;
use crate::interceptors::extract_token;
use crate::state::SharedState;

pub struct ApiKeyServiceImpl {
    state: SharedState,
}

impl ApiKeyServiceImpl {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }

    pub fn into_server(self) -> ApiKeyServiceServer<Self> {
        ApiKeyServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl ApiKeyService for ApiKeyServiceImpl {
    async fn list_api_keys(
        &self,
        request: Request<ListApiKeysRequest>,
    ) -> Result<Response<ListApiKeysResponse>, Status> {
        let token = extract_token(&request)?;

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let keys = self
            .state
            .auth
            .list_api_keys(user.id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(ListApiKeysResponse {
            api_keys: keys.into_iter().map(|k| k.into()).collect(),
        }))
    }

    async fn create_api_key(
        &self,
        request: Request<CreateApiKeyRequest>,
    ) -> Result<Response<CreateApiKeyResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let expires_at = req
            .expires_in_days
            .map(|days| chrono::Utc::now() + chrono::Duration::days(days));

        let (key, secret) = self
            .state
            .auth
            .create_api_key(user.id, &req.name, req.scopes, None, expires_at)
            .await
            .map_err(to_status)?;

        Ok(Response::new(CreateApiKeyResponse {
            api_key: Some(key.into()),
            secret,
        }))
    }

    async fn update_api_key(
        &self,
        request: Request<UpdateApiKeyRequest>,
    ) -> Result<Response<ApiKeyResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let key_id =
            Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid API key ID"))?;

        let scopes = if req.scopes.is_empty() {
            None
        } else {
            Some(req.scopes)
        };

        let key = self
            .state
            .auth
            .update_api_key(user.id, key_id, req.name, scopes)
            .await
            .map_err(to_status)?;

        Ok(Response::new(ApiKeyResponse {
            api_key: Some(key.into()),
        }))
    }

    async fn delete_api_key(
        &self,
        request: Request<DeleteApiKeyRequest>,
    ) -> Result<Response<MessageResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let key_id =
            Uuid::parse_str(&req.id).map_err(|_| Status::invalid_argument("Invalid API key ID"))?;

        self.state
            .auth
            .delete_api_key(user.id, key_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(MessageResponse {
            message: "API key deleted".to_string(),
        }))
    }
}
