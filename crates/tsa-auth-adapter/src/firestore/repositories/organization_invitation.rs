use async_trait::async_trait;
use chrono::Utc;
use tsa_auth_core::{
    InvitationStatus, OrganizationInvitation, OrganizationInvitationRepository, Result,
};
use uuid::Uuid;

use super::super::{client::FirestoreClient, COLLECTION_ORGANIZATION_INVITATIONS};

#[derive(Clone)]
pub struct FirestoreOrganizationInvitationRepository {
    client: FirestoreClient,
}

impl FirestoreOrganizationInvitationRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl OrganizationInvitationRepository for FirestoreOrganizationInvitationRepository {
    async fn create(&self, invitation: &OrganizationInvitation) -> Result<OrganizationInvitation> {
        self.client
            .create_document(
                COLLECTION_ORGANIZATION_INVITATIONS,
                &invitation.id.to_string(),
                invitation,
            )
            .await?;
        Ok(invitation.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<OrganizationInvitation>> {
        self.client
            .get_document(COLLECTION_ORGANIZATION_INVITATIONS, &id.to_string())
            .await
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<OrganizationInvitation>> {
        self.client
            .find_by_field(
                COLLECTION_ORGANIZATION_INVITATIONS,
                "token_hash",
                token_hash,
            )
            .await
    }

    async fn find_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationInvitation>> {
        self.client
            .find_all_by_field(
                COLLECTION_ORGANIZATION_INVITATIONS,
                "organization_id",
                &organization_id.to_string(),
            )
            .await
    }

    async fn find_by_email(&self, email: &str) -> Result<Vec<OrganizationInvitation>> {
        self.client
            .find_all_by_field(COLLECTION_ORGANIZATION_INVITATIONS, "email", email)
            .await
    }

    async fn find_pending_by_org_and_email(
        &self,
        organization_id: Uuid,
        email: &str,
    ) -> Result<Option<OrganizationInvitation>> {
        let invitations: Vec<OrganizationInvitation> = self
            .client
            .list_documents(COLLECTION_ORGANIZATION_INVITATIONS)
            .await?;
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
            .update_document(
                COLLECTION_ORGANIZATION_INVITATIONS,
                &invitation.id.to_string(),
                invitation,
            )
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
            .delete_document(COLLECTION_ORGANIZATION_INVITATIONS, &id.to_string())
            .await
    }

    async fn delete_expired(&self) -> Result<u64> {
        let invitations: Vec<OrganizationInvitation> = self
            .client
            .list_documents(COLLECTION_ORGANIZATION_INVITATIONS)
            .await?;
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
