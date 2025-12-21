use axum::{extract::State, Json};
use serde::Deserialize;

use crate::{
    error::ApiError,
    extractors::{AuthUser, ClientInfo},
    responses::{AuthResponse, MessageResponse, SessionResponse, TwoFactorSetupResponse},
    state::SharedState,
};

#[derive(Deserialize)]
pub struct SignupRequest {
    pub email: String,
    pub password: String,
    pub name: Option<String>,
}

pub async fn signup(
    State(state): State<SharedState>,
    Json(req): Json<SignupRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let (user, session, token) = state
        .auth
        .signup(&req.email, &req.password, req.name)
        .await?;

    Ok(Json(AuthResponse {
        user: user.into(),
        session: session.into(),
        token,
    }))
}

#[derive(Deserialize)]
pub struct SigninRequest {
    pub email: String,
    pub password: String,
}

pub async fn signin(
    State(state): State<SharedState>,
    client: ClientInfo,
    Json(req): Json<SigninRequest>,
) -> Result<Json<AuthResponse>, ApiError> {
    let (user, session, token) = state
        .auth
        .signin(
            &req.email,
            &req.password,
            client.ip_address,
            client.user_agent,
        )
        .await?;

    Ok(Json(AuthResponse {
        user: user.into(),
        session: session.into(),
        token,
    }))
}

pub async fn signout(
    State(state): State<SharedState>,
    auth: AuthUser,
) -> Result<Json<MessageResponse>, ApiError> {
    state.auth.revoke_session(auth.session.id).await?;
    Ok(Json(MessageResponse::new("Signed out successfully")))
}

pub async fn refresh_session(
    State(state): State<SharedState>,
    auth: AuthUser,
) -> Result<Json<SessionResponse>, ApiError> {
    let sessions = state.auth.get_user_sessions(auth.user.id).await?;
    let session = sessions
        .into_iter()
        .find(|s| s.id == auth.session.id)
        .ok_or_else(|| ApiError::unauthorized("Session not found"))?;

    Ok(Json(session.into()))
}

pub async fn setup_2fa(
    State(state): State<SharedState>,
    auth: AuthUser,
) -> Result<Json<TwoFactorSetupResponse>, ApiError> {
    let setup = state.auth.enable_2fa(auth.user.id).await?;

    Ok(Json(TwoFactorSetupResponse {
        secret: setup.secret,
        otpauth_url: setup.otpauth_url,
        backup_codes: setup.backup_codes,
    }))
}

#[derive(Deserialize)]
pub struct Verify2faRequest {
    pub code: String,
}

pub async fn verify_2fa(
    State(state): State<SharedState>,
    auth: AuthUser,
    Json(req): Json<Verify2faRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    state.auth.verify_2fa(auth.user.id, &req.code).await?;
    Ok(Json(MessageResponse::new(
        "Two-factor authentication enabled",
    )))
}

#[derive(Deserialize)]
pub struct Disable2faRequest {
    pub code: String,
}

pub async fn disable_2fa(
    State(state): State<SharedState>,
    auth: AuthUser,
    Json(req): Json<Disable2faRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    state.auth.disable_2fa(auth.user.id, &req.code).await?;
    Ok(Json(MessageResponse::new(
        "Two-factor authentication disabled",
    )))
}

#[derive(Deserialize)]
pub struct ChangePasswordRequest {
    pub current_password: String,
    pub new_password: String,
    pub revoke_other_sessions: Option<bool>,
}

pub async fn change_password(
    State(state): State<SharedState>,
    auth: AuthUser,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .auth
        .change_password(
            auth.user.id,
            &req.current_password,
            &req.new_password,
            req.revoke_other_sessions.unwrap_or(false),
            Some(auth.session.id),
        )
        .await?;

    Ok(Json(MessageResponse::new("Password changed successfully")))
}
