use async_trait::async_trait;
use chrono::Utc;
use tsa_auth_core::{
    InvitationStatus, OrganizationInvitation, OrganizationInvitationRepository, Result,
};
use uuid::Uuid;

use super::super::client::BigtableClient;

const ENTITY_TYPE: &str = "organization_invitation";

#[derive(Clone)]
pub struct BigtableOrganizationInvitationRepository {
    client: BigtableClient,
}

impl BigtableOrganizationInvitationRepository {
    pub fn new(client: BigtableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl OrganizationInvitationRepository for BigtableOrganizationInvitationRepository {
    async fn create(&self, invitation: &OrganizationInvitation) -> Result<OrganizationInvitation> {
        self.client
            .create_entity(ENTITY_TYPE, &invitation.id.to_string(), invitation)
            .await?;
        Ok(invitation.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<OrganizationInvitation>> {
        self.client.get_entity(ENTITY_TYPE, &id.to_string()).await
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<OrganizationInvitation>> {
        self.client
            .find_by_field(ENTITY_TYPE, "token_hash", token_hash)
            .await
    }

    async fn find_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationInvitation>> {
        self.client
            .find_all_by_field(ENTITY_TYPE, "organization_id", &organization_id.to_string())
            .await
    }

    async fn find_by_email(&self, email: &str) -> Result<Vec<OrganizationInvitation>> {
        self.client
            .find_all_by_field(ENTITY_TYPE, "email", email)
            .await
    }

    async fn find_pending_by_org_and_email(
        &self,
        organization_id: Uuid,
        email: &str,
    ) -> Result<Option<OrganizationInvitation>> {
        let invitations: Vec<OrganizationInvitation> =
            self.client.list_entities(ENTITY_TYPE).await?;
        for invitation in invitations {
            if invitation.organization_id == organization_id
                && invitation.email == email
                && invitation.status == InvitationStatus::Pending
            {
                return Ok(Some(invitation));
            }
        }
        Ok(None)
    }

    async fn update(&self, invitation: &OrganizationInvitation) -> Result<OrganizationInvitation> {
        self.client
            .update_entity(ENTITY_TYPE, &invitation.id.to_string(), invitation)
            .await?;
        Ok(invitation.clone())
    }

    async fn update_status(&self, id: Uuid, status: InvitationStatus) -> Result<()> {
        if let Some(mut invitation) = self.find_by_id(id).await? {
            invitation.status = status;
            self.update(&invitation).await?;
        }
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_entity(ENTITY_TYPE, &id.to_string())
            .await
    }

    async fn delete_expired(&self) -> Result<u64> {
        let invitations: Vec<OrganizationInvitation> =
            self.client.list_entities(ENTITY_TYPE).await?;
        let now = Utc::now();
        let mut count = 0u64;
        for invitation in invitations {
            if invitation.expires_at < now {
                self.delete(invitation.id).await?;
                count += 1;
            }
        }
        Ok(count)
    }
}
