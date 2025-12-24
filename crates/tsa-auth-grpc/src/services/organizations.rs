use tonic::{Request, Response, Status};
use tsa_auth_core::OrganizationRole;
use tsa_auth_proto::{
    member_with_user, AddMemberRequest, CreateOrganizationRequest, DeleteOrganizationRequest,
    GetOrganizationRequest, ListMembersRequest, ListMembersResponse, ListOrganizationsRequest,
    ListOrganizationsResponse, MemberResponse, MessageResponse, OrganizationResponse,
    OrganizationService, OrganizationServiceServer, RemoveMemberRequest, UpdateMemberRequest,
    UpdateOrganizationRequest,
};
use uuid::Uuid;

use crate::error::to_status;
use crate::interceptors::extract_token;
use crate::state::SharedState;

pub struct OrganizationServiceImpl {
    state: SharedState,
}

impl OrganizationServiceImpl {
    pub fn new(state: SharedState) -> Self {
        Self { state }
    }

    pub fn into_server(self) -> OrganizationServiceServer<Self> {
        OrganizationServiceServer::new(self)
    }
}

#[tonic::async_trait]
impl OrganizationService for OrganizationServiceImpl {
    async fn list_organizations(
        &self,
        request: Request<ListOrganizationsRequest>,
    ) -> Result<Response<ListOrganizationsResponse>, Status> {
        let token = extract_token(&request)?;

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let orgs = self
            .state
            .auth
            .get_user_organizations(user.id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(ListOrganizationsResponse {
            organizations: orgs.into_iter().map(|(org, _role)| org.into()).collect(),
        }))
    }

    async fn create_organization(
        &self,
        request: Request<CreateOrganizationRequest>,
    ) -> Result<Response<OrganizationResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let (org, _) = self
            .state
            .auth
            .create_organization(user.id, &req.name, &req.slug)
            .await
            .map_err(to_status)?;

        Ok(Response::new(OrganizationResponse {
            organization: Some(org.into()),
        }))
    }

    async fn get_organization(
        &self,
        request: Request<GetOrganizationRequest>,
    ) -> Result<Response<OrganizationResponse>, Status> {
        let req = request.into_inner();

        let org = self
            .state
            .auth
            .get_organization_by_slug(&req.slug)
            .await
            .map_err(to_status)?;

        Ok(Response::new(OrganizationResponse {
            organization: Some(org.into()),
        }))
    }

    async fn update_organization(
        &self,
        request: Request<UpdateOrganizationRequest>,
    ) -> Result<Response<OrganizationResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let org_id = Uuid::parse_str(&req.id)
            .map_err(|_| Status::invalid_argument("Invalid organization ID"))?;

        let org = self
            .state
            .auth
            .update_organization(user.id, org_id, req.name, req.logo, None)
            .await
            .map_err(to_status)?;

        Ok(Response::new(OrganizationResponse {
            organization: Some(org.into()),
        }))
    }

    async fn delete_organization(
        &self,
        request: Request<DeleteOrganizationRequest>,
    ) -> Result<Response<MessageResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let org_id = Uuid::parse_str(&req.id)
            .map_err(|_| Status::invalid_argument("Invalid organization ID"))?;

        self.state
            .auth
            .delete_organization(user.id, org_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(MessageResponse {
            message: "Organization deleted".to_string(),
        }))
    }

    async fn list_members(
        &self,
        request: Request<ListMembersRequest>,
    ) -> Result<Response<ListMembersResponse>, Status> {
        let req = request.into_inner();

        let org_id = Uuid::parse_str(&req.organization_id)
            .map_err(|_| Status::invalid_argument("Invalid organization ID"))?;

        let members = self
            .state
            .auth
            .get_organization_members(org_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(ListMembersResponse {
            members: members
                .into_iter()
                .map(|(user, member)| member_with_user(member, Some(user)))
                .collect(),
        }))
    }

    async fn add_member(
        &self,
        request: Request<AddMemberRequest>,
    ) -> Result<Response<MemberResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let org_id = Uuid::parse_str(&req.organization_id)
            .map_err(|_| Status::invalid_argument("Invalid organization ID"))?;
        let target_user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user ID"))?;
        let role: OrganizationRole = req
            .role
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid role"))?;

        let member = self
            .state
            .auth
            .add_organization_member(user.id, org_id, target_user_id, role)
            .await
            .map_err(to_status)?;

        Ok(Response::new(MemberResponse {
            member: Some(member.into()),
        }))
    }

    async fn update_member(
        &self,
        request: Request<UpdateMemberRequest>,
    ) -> Result<Response<MemberResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let org_id = Uuid::parse_str(&req.organization_id)
            .map_err(|_| Status::invalid_argument("Invalid organization ID"))?;
        let target_user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user ID"))?;
        let role: OrganizationRole = req
            .role
            .parse()
            .map_err(|_| Status::invalid_argument("Invalid role"))?;

        let member = self
            .state
            .auth
            .update_member_role(user.id, org_id, target_user_id, role)
            .await
            .map_err(to_status)?;

        Ok(Response::new(MemberResponse {
            member: Some(member.into()),
        }))
    }

    async fn remove_member(
        &self,
        request: Request<RemoveMemberRequest>,
    ) -> Result<Response<MessageResponse>, Status> {
        let token = extract_token(&request)?;
        let req = request.into_inner();

        let (user, _) = self
            .state
            .auth
            .validate_session(&token)
            .await
            .map_err(to_status)?;

        let org_id = Uuid::parse_str(&req.organization_id)
            .map_err(|_| Status::invalid_argument("Invalid organization ID"))?;
        let target_user_id = Uuid::parse_str(&req.user_id)
            .map_err(|_| Status::invalid_argument("Invalid user ID"))?;

        self.state
            .auth
            .remove_organization_member(user.id, org_id, target_user_id)
            .await
            .map_err(to_status)?;

        Ok(Response::new(MessageResponse {
            message: "Member removed".to_string(),
        }))
    }
}
