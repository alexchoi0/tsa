use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::{bson::doc, Collection};
use tsa_auth_core::{OrganizationMember, OrganizationMemberRepository, Result, TsaError};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbOrganizationMemberRepository {
    collection: Collection<OrganizationMember>,
}

impl MongoDbOrganizationMemberRepository {
    pub fn new(collection: Collection<OrganizationMember>) -> Self {
        Self { collection }
    }
}

#[async_trait]
impl OrganizationMemberRepository for MongoDbOrganizationMemberRepository {
    async fn create(&self, member: &OrganizationMember) -> Result<OrganizationMember> {
        self.collection
            .insert_one(member)
            .await
            .map_err(|e| {
                if e.to_string().contains("duplicate key") {
                    TsaError::AlreadyOrganizationMember
                } else {
                    TsaError::Database(e.to_string())
                }
            })?;
        Ok(member.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<OrganizationMember>> {
        self.collection
            .find_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_org_and_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMember>> {
        self.collection
            .find_one(doc! {
                "organization_id": organization_id,
                "user_id": user_id
            })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationMember>> {
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

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<OrganizationMember>> {
        let cursor = self
            .collection
            .find(doc! { "user_id": user_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        cursor
            .try_collect()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn update(&self, member: &OrganizationMember) -> Result<OrganizationMember> {
        self.collection
            .replace_one(doc! { "id": member.id }, member)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(member.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.collection
            .delete_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }

    async fn delete_by_organization(&self, organization_id: Uuid) -> Result<()> {
        self.collection
            .delete_many(doc! { "organization_id": organization_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }
}
