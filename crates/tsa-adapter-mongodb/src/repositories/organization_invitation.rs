use async_trait::async_trait;
use chrono::Utc;
use futures::TryStreamExt;
use mongodb::{bson::doc, Collection};
use tsa_core::{
    InvitationStatus, OrganizationInvitation, OrganizationInvitationRepository, Result, TsaError,
};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbOrganizationInvitationRepository {
    collection: Collection<OrganizationInvitation>,
}

impl MongoDbOrganizationInvitationRepository {
    pub fn new(collection: Collection<OrganizationInvitation>) -> Self {
        Self { collection }
    }
}

#[async_trait]
impl OrganizationInvitationRepository for MongoDbOrganizationInvitationRepository {
    async fn create(&self, invitation: &OrganizationInvitation) -> Result<OrganizationInvitation> {
        self.collection
            .insert_one(invitation)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(invitation.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<OrganizationInvitation>> {
        self.collection
            .find_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<OrganizationInvitation>> {
        self.collection
            .find_one(doc! { "token_hash": token_hash })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationInvitation>> {
        let cursor = self
            .collection
            .find(doc! { "organization_id": organization_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        cursor
            .try_collect()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_email(&self, email: &str) -> Result<Vec<OrganizationInvitation>> {
        let cursor = self
            .collection
            .find(doc! { "email": email })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        cursor
            .try_collect()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_pending_by_org_and_email(
        &self,
        organization_id: Uuid,
        email: &str,
    ) -> Result<Option<OrganizationInvitation>> {
        self.collection
            .find_one(doc! {
                "organization_id": organization_id,
                "email": email,
                "status": "Pending"
            })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn update(&self, invitation: &OrganizationInvitation) -> Result<OrganizationInvitation> {
        self.collection
            .replace_one(doc! { "id": invitation.id }, invitation)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(invitation.clone())
    }

    async fn update_status(&self, id: Uuid, status: InvitationStatus) -> Result<()> {
        self.collection
            .update_one(
                doc! { "id": id },
                doc! { "$set": { "status": status.to_string() } },
            )
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.collection
            .delete_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64> {
        let result = self
            .collection
            .delete_many(doc! { "expires_at": { "$lt": Utc::now() } })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(result.deleted_count)
    }
}
