use tonic::{Request, Response, Status};
use tsa_auth_proto::{
    AuthResponse, AuthService, AuthServiceServer, ChangePasswordRequest, Disable2faRequest,
    MessageResponse, RefreshSessionRequest, RefreshSessionResponse, Setup2faRequest, SigninRequest,
    SignoutRequest, SignupRequest, TwoFactorSetupResponse, Verify2faRequest,
};

use crate::error::to_status;
use crate::interceptors::{extract_client_info, extract_token};
use crate::state::SharedState;

pub struct AuthServiceImpl {
    state: SharedState,
}

impl AuthServiceImpl {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }

    pub fn into_server(self) -> AuthServiceServer<Self> {
        AuthServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl AuthService for AuthServiceImpl {
    async fn signup(
        &self,
        request: Request<SignupRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let req = request.into_inner();

        let (user, session, token) = self
            .state
            .auth
            .signup(&req.email, &req.password, req.name)
            .await
            .map_err(to_status)?;

        Ok(Response::new(AuthResponse {
            user: Some(user.into()),
            session: Some(session.into()),
            token,
        }))
    }

    async fn signin(
        &self,
        request: Request<SigninRequest>,
    ) -> Result<Response<AuthResponse>, Status> {
        let client = extract_client_info(&request);
        let req = request.into_inner();

        let (user, session, token) = self
            .state
            .auth
            .signin(
                &req.email,
                &req.password,
                client.ip_address,
                client.user_agent,
            )
            .await
            .map_err(to_status)?;

        Ok(Response::new(AuthResponse {
            user: Some(user.into()),
            session: Some(session.into()),
            token,
        }))
    }

    async fn signout(
        &self,
        request: Request<SignoutRequest>,
    ) -> Result<Response<MessageResponse>, Status> {
        let token = extract_token(&request)?;

        let (_, session) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        self.state
            .auth
            .revoke_session(session.id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(MessageResponse {
            message: "Signed out successfully".to_string(),
        }))
    }

    async fn refresh_session(
        &self,
        request: Request<RefreshSessionRequest>,
    ) -> Result<Response<RefreshSessionResponse>, Status> {
        let token = extract_token(&request)?;

        let (user, session) = self
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

        let current_session = sessions
            .into_iter()
            .find(|s| s.id == session.id)
            .ok_or_else(|| Status::unauthenticated("Session not found"))?;

        Ok(Response::new(RefreshSessionResponse {
            session: Some(current_session.into()),
            token,
        }))
    }

    async fn setup2fa(
        &self,
        request: Request<Setup2faRequest>,
    ) -> Result<Response<TwoFactorSetupResponse>, Status> {
        let token = extract_token(&request)?;

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let setup = self
            .state
            .auth
            .enable_2fa(user.id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(TwoFactorSetupResponse {
            secret: setup.secret,
            otpauth_url: setup.otpauth_url,
            backup_codes: setup.backup_codes,
        }))
    }

    async fn verify2fa(
        &self,
        request: Request<Verify2faRequest>,
    ) -> Result<Response<MessageResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        self.state
            .auth
            .verify_2fa(user.id, &req.code)
            .await
            .map_err(to_status)?;

        Ok(Response::new(MessageResponse {
            message: "Two-factor authentication enabled".to_string(),
        }))
    }

    async fn disable2fa(
        &self,
        request: Request<Disable2faRequest>,
    ) -> Result<Response<MessageResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        self.state
            .auth
            .disable_2fa(user.id, &req.code)
            .await
            .map_err(to_status)?;

        Ok(Response::new(MessageResponse {
            message: "Two-factor authentication disabled".to_string(),
        }))
    }

    async fn change_password(
        &self,
        request: Request<ChangePasswordRequest>,
    ) -> Result<Response<MessageResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, session) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        self.state
            .auth
            .change_password(
                user.id,
                &req.current_password,
                &req.new_password,
                req.revoke_other_sessions,
                Some(session.id),
            )
            .await
            .map_err(to_status)?;

        Ok(Response::new(MessageResponse {
            message: "Password changed successfully".to_string(),
        }))
    }
}
