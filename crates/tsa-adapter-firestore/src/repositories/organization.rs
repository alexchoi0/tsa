use async_trait::async_trait;
use tsa_core::{Organization, OrganizationRepository, Result};
use uuid::Uuid;

use crate::{client::FirestoreClient, COLLECTION_ORGANIZATIONS};

#[derive(Clone)]
pub struct FirestoreOrganizationRepository {
    client: FirestoreClient,
}

impl FirestoreOrganizationRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl OrganizationRepository for FirestoreOrganizationRepository {
    async fn create(&self, organization: &Organization) -> Result<Organization> {
        self.client
            .create_document(
                COLLECTION_ORGANIZATIONS,
                &organization.id.to_string(),
                organization,
            )
            .await?;
        Ok(organization.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>> {
        self.client
            .get_document(COLLECTION_ORGANIZATIONS, &id.to_string())
            .await
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>> {
        self.client
            .find_by_field(COLLECTION_ORGANIZATIONS, "slug", slug)
            .await
    }

    async fn update(&self, organization: &Organization) -> Result<Organization> {
        self.client
            .update_document(
                COLLECTION_ORGANIZATIONS,
                &organization.id.to_string(),
                organization,
            )
            .await?;
        Ok(organization.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_document(COLLECTION_ORGANIZATIONS, &id.to_string())
            .await
    }
}
