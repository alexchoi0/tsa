use async_trait::async_trait;
use mongodb::{bson::doc, Collection};
use tsa_auth_core::{Organization, OrganizationRepository, Result, TsaError};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbOrganizationRepository {
    collection: Collection<Organization>,
}

impl MongoDbOrganizationRepository {
    pub fn new(collection: Collection<Organization>) -> Self {
        Self { collection }
    }
}

#[async_trait]
impl OrganizationRepository for MongoDbOrganizationRepository {
    async fn create(&self, organization: &Organization) -> Result<Organization> {
        self.collection
            .insert_one(organization)
            .await
            .map_err(|e| {
                if e.to_string().contains("duplicate key") {
                    TsaError::OrganizationAlreadyExists
                } else {
                    TsaError::Database(e.to_string())
                }
            })?;
        Ok(organization.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>> {
        self.collection
            .find_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>> {
        self.collection
            .find_one(doc! { "slug": slug })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn update(&self, organization: &Organization) -> Result<Organization> {
        self.collection
            .replace_one(doc! { "id": organization.id }, organization)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(organization.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.collection
            .delete_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }
}
