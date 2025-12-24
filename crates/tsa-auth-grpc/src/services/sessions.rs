use tonic::{Request, Response, Status};
use tsa_auth_proto::{
    ListSessionsRequest, ListSessionsResponse, MessageResponse, RevokeAllSessionsRequest,
    RevokeSessionRequest, SessionService, SessionServiceServer,
};
use uuid::Uuid;

use crate::error::to_status;
use crate::interceptors::extract_token;
use crate::state::SharedState;

pub struct SessionServiceImpl {
    state: SharedState,
}

impl SessionServiceImpl {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }

    pub fn into_server(self) -> SessionServiceServer<Self> {
        SessionServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl SessionService for SessionServiceImpl {
    async fn list_sessions(
        &self,
        request: Request<ListSessionsRequest>,
    ) -> Result<Response<ListSessionsResponse>, Status> {
        let token = extract_token(&request)?;

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let sessions = self
            .state
            .auth
            .get_user_sessions(user.id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(ListSessionsResponse {
            sessions: sessions.into_iter().map(|s| s.into()).collect(),
        }))
    }

    async fn revoke_session(
        &self,
        request: Request<RevokeSessionRequest>,
    ) -> Result<Response<MessageResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let session_id = Uuid::parse_str(&req.session_id)
            .map_err(|_| Status::invalid_argument("Invalid session ID"))?;

        let sessions = self
            .state
            .auth
            .get_user_sessions(user.id)
            .await
            .map_err(to_status)?;

        if !sessions.iter().any(|s| s.id == session_id) {
            return Err(Status::unauthenticated(
                "Session not found or does not belong to you",
            ));
        }

        self.state
            .auth
            .revoke_session(session_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(MessageResponse {
            message: "Session revoked".to_string(),
        }))
    }

    async fn revoke_all_sessions(
        &self,
        request: Request<RevokeAllSessionsRequest>,
    ) -> Result<Response<MessageResponse>, Status> {
        let token = extract_token(&request)?;

        let (user, session) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        self.state
            .auth
            .revoke_other_sessions(user.id, session.id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(MessageResponse {
            message: "All other sessions revoked".to_string(),
        }))
    }
}
