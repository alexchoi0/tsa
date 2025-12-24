use tonic::{Request, Response, Status};
use tsa_auth_proto::{
    GetCurrentUserRequest, UpdateCurrentUserRequest, UserResponse, UserService, UserServiceServer,
};

use crate::error::to_status;
use crate::interceptors::extract_token;
use crate::state::SharedState;

pub struct UserServiceImpl {
    state: SharedState,
}

impl UserServiceImpl {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }

    pub fn into_server(self) -> UserServiceServer<Self> {
        UserServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl UserService for UserServiceImpl {
    async fn get_current_user(
        &self,
        request: Request<GetCurrentUserRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        let token = extract_token(&request)?;

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        Ok(Response::new(UserResponse {
            user: Some(user.into()),
        }))
    }

    async fn update_current_user(
        &self,
        request: Request<UpdateCurrentUserRequest>,
    ) -> Result<Response<UserResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (mut user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        if let Some(name) = req.name {
            user.name = Some(name);
        }

        if let Some(phone) = req.phone {
            user = self
                .state
                .auth
                .set_user_phone(user.id, &phone)
                .await
                .map_err(to_status)?;
        }

        Ok(Response::new(UserResponse {
            user: Some(user.into()),
        }))
    }
}
