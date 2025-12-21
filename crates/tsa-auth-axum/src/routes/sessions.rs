use axum::{
    extract::{Path, State},
    Json,
};
use uuid::Uuid;

use crate::{
    error::ApiError,
    extractors::AuthUser,
    responses::{MessageResponse, SessionResponse},
    state::SharedState,
};

pub async fn list_sessions(
    State(state): State<SharedState>,
    auth: AuthUser,
) -> Result<Json<Vec<SessionResponse>>, ApiError> {
    let sessions = state.auth.get_user_sessions(auth.user.id).await?;
    Ok(Json(sessions.into_iter().map(|s| s.into()).collect()))
}

pub async fn revoke_session(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(session_id): Path<Uuid>,
) -> Result<Json<MessageResponse>, ApiError> {
    let sessions = state.auth.get_user_sessions(auth.user.id).await?;

    if !sessions.iter().any(|s| s.id == session_id) {
        return Err(ApiError::unauthorized("Session not found or does not belong to you"));
    }

    state.auth.revoke_session(session_id).await?;
    Ok(Json(MessageResponse::new("Session revoked")))
}

pub async fn revoke_all_sessions(
    State(state): State<SharedState>,
    auth: AuthUser,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .auth
        .revoke_other_sessions(auth.user.id, auth.session.id)
        .await?;

    Ok(Json(MessageResponse::new("All other sessions revoked")))
}
