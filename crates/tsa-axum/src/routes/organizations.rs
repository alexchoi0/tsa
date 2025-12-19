use axum::{
    extract::{Path, State},
    Json,
};
use serde::Deserialize;
use tsa_core::OrganizationRole;
use uuid::Uuid;

use crate::{
    error::ApiError,
    extractors::AuthUser,
    responses::{MemberResponse, MessageResponse, OrganizationResponse},
    state::SharedState,
};

pub async fn list_organizations(
    State(state): State<SharedState>,
    auth: AuthUser,
) -> Result<Json<Vec<OrganizationResponse>>, ApiError> {
    let orgs = state.auth.get_user_organizations(auth.user.id).await?;
    Ok(Json(orgs.into_iter().map(|o| o.into()).collect()))
}

#[derive(Deserialize)]
pub struct CreateOrganizationRequest {
    pub name: String,
    pub slug: String,
}

pub async fn create_organization(
    State(state): State<SharedState>,
    auth: AuthUser,
    Json(req): Json<CreateOrganizationRequest>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    let (org, _) = state
        .auth
        .create_organization(auth.user.id, &req.name, &req.slug)
        .await?;

    Ok(Json(org.into()))
}

pub async fn get_organization(
    State(state): State<SharedState>,
    Path(slug): Path<String>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    let org = state.auth.get_organization_by_slug(&slug).await?;
    Ok(Json(org.into()))
}

#[derive(Deserialize)]
pub struct UpdateOrganizationRequest {
    pub name: Option<String>,
    pub logo: Option<String>,
}

pub async fn update_organization(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateOrganizationRequest>,
) -> Result<Json<OrganizationResponse>, ApiError> {
    let org = state
        .auth
        .update_organization(auth.user.id, id, req.name, req.logo, None)
        .await?;

    Ok(Json(org.into()))
}

pub async fn delete_organization(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
) -> Result<Json<MessageResponse>, ApiError> {
    state.auth.delete_organization(auth.user.id, id).await?;
    Ok(Json(MessageResponse::new("Organization deleted")))
}

pub async fn list_members(
    State(state): State<SharedState>,
    Path(id): Path<Uuid>,
) -> Result<Json<Vec<MemberResponse>>, ApiError> {
    let members = state.auth.get_organization_members(id).await?;
    Ok(Json(
        members
            .into_iter()
            .map(|(user, member)| MemberResponse::with_user(member, user))
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct AddMemberRequest {
    pub user_id: Uuid,
    pub role: String,
}

pub async fn add_member(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path(id): Path<Uuid>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<MemberResponse>, ApiError> {
    let role: OrganizationRole = req
        .role
        .parse()
        .map_err(|_| ApiError::bad_request("Invalid role"))?;

    let member = state
        .auth
        .add_organization_member(auth.user.id, id, req.user_id, role)
        .await?;

    Ok(Json(member.into()))
}

#[derive(Deserialize)]
pub struct UpdateMemberRequest {
    pub role: String,
}

pub async fn update_member(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<Json<MemberResponse>, ApiError> {
    let role: OrganizationRole = req
        .role
        .parse()
        .map_err(|_| ApiError::bad_request("Invalid role"))?;

    let member = state
        .auth
        .update_member_role(auth.user.id, org_id, user_id, role)
        .await?;

    Ok(Json(member.into()))
}

pub async fn remove_member(
    State(state): State<SharedState>,
    auth: AuthUser,
    Path((org_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<MessageResponse>, ApiError> {
    state
        .auth
        .remove_organization_member(auth.user.id, org_id, user_id)
        .await?;

    Ok(Json(MessageResponse::new("Member removed")))
}
