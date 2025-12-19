use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use uuid::Uuid;

use crate::{
    error::ApiError,
    extractors::AuthUser,
    responses::{ApiKeyCreatedResponse, ApiKeyResponse, MessageResponse, UserResponse},
    state::SharedState,
};

pub async fn get_current_user(auth: AuthUser) -> Json<UserResponse> {
    Json(auth.user.into())
}

#[derive(Deserialize)]
pub struct UpdateUserRequest {
    pub name: Option<String>,
    pub phone: Option<String>,
}

pub async fn update_current_user(
    State(state): State<SharedState>,
    auth: AuthUser,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserResponse>, ApiError> {
    let mut user = auth.user;

    if let Some(name) = req.name {
        user.name = Some(name);
    }

    if let Some(phone) = req.phone {
        let updated = state.auth.set_user_phone(user.id, &phone).await?;
        user = updated;
    }

    Ok(Json(user.into()))
}

pub async fn list_api_keys(
    State(state): State<SharedState>,
    auth: AuthUser,
) -> Result<Json<Vec<ApiKeyResponse>>, ApiError> {
    let keys = state.auth.list_api_keys(auth.user.id).await?;
    Ok(Json(keys.into_iter().map(|k| k.into()).collect()))
}

#[derive(Deserialize)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub scopes: Option<Vec<String>>,
    pub expires_in_days: Option<i64>,
}

pub async fn create_api_key(
    State(state): State<SharedState>,
    auth: AuthUser,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<Json<ApiKeyCreatedResponse>, ApiError> {
    let expires_at = req.expires_in_days.map(|days| {
        chrono::Utc::now() + chrono::Duration::days(days)
    });

    let (key, secret) = state
        .auth
        .create_api_key(
            auth.user.id,
            &req.name,
            req.scopes.unwrap_or_default(),
            None,
            expires_at,
        )
        .await?;

    Ok(Json(ApiKeyCreatedResponse {
        key: key.into(),
        secret,
    }))
}

pub async fn delete_api_key(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<MessageResponse>, ApiError> {
    state.auth.delete_api_key(auth.user.id, id).await?;
    Ok(Json(MessageResponse::new("API key deleted")))
}
