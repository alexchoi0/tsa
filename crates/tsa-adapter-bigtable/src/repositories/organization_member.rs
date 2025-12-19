use async_trait::async_trait;
use tsa_core::{OrganizationMember, OrganizationMemberRepository, Result};
use uuid::Uuid;

use crate::client::BigtableClient;

const ENTITY_TYPE: &str = "organization_member";

#[derive(Clone)]
pub struct BigtableOrganizationMemberRepository {
    client: BigtableClient,
}

impl BigtableOrganizationMemberRepository {
    pub fn new(client: BigtableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl OrganizationMemberRepository for BigtableOrganizationMemberRepository {
    async fn create(&self, member: &OrganizationMember) -> Result<OrganizationMember> {
        self.client
            .create_entity(ENTITY_TYPE, &member.id.to_string(), member)
            .await?;
        Ok(member.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<OrganizationMember>> {
        self.client.get_entity(ENTITY_TYPE, &id.to_string()).await
    }

    async fn find_by_org_and_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMember>> {
        let members: Vec<OrganizationMember> = self.client.list_entities(ENTITY_TYPE).await?;
        for member in members {
            if member.organization_id == organization_id && member.user_id == user_id {
                return Ok(Some(member));
            }
        }
        Ok(None)
    }

    async fn find_by_organization(&self, organization_id: Uuid) -> Result<Vec<OrganizationMember>> {
        self.client
            .find_all_by_field(ENTITY_TYPE, "organization_id", &organization_id.to_string())
            .await
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<OrganizationMember>> {
        self.client
            .find_all_by_field(ENTITY_TYPE, "user_id", &user_id.to_string())
            .await
    }

    async fn update(&self, member: &OrganizationMember) -> Result<OrganizationMember> {
        self.client
            .update_entity(ENTITY_TYPE, &member.id.to_string(), member)
            .await?;
        Ok(member.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_entity(ENTITY_TYPE, &id.to_string())
            .await
    }

    async fn delete_by_organization(&self, organization_id: Uuid) -> Result<()> {
        let members = self.find_by_organization(organization_id).await?;
        for member in members {
            self.delete(member.id).await?;
        }
        Ok(())
    }
}
