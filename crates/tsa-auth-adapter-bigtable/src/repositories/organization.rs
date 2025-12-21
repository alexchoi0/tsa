use async_trait::async_trait;
use tsa_auth_core::{Organization, OrganizationRepository, Result};
use uuid::Uuid;

use crate::client::BigtableClient;

const ENTITY_TYPE: &str = "organization";

#[derive(Clone)]
pub struct BigtableOrganizationRepository {
    client: BigtableClient,
}

impl BigtableOrganizationRepository {
    pub fn new(client: BigtableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl OrganizationRepository for BigtableOrganizationRepository {
    async fn create(&self, organization: &Organization) -> Result<Organization> {
        self.client
            .create_entity(ENTITY_TYPE, &organization.id.to_string(), organization)
            .await?;
        Ok(organization.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>> {
        self.client.get_entity(ENTITY_TYPE, &id.to_string()).await
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>> {
        self.client.find_by_field(ENTITY_TYPE, "slug", slug).await
    }

    async fn update(&self, organization: &Organization) -> Result<Organization> {
        self.client
            .update_entity(ENTITY_TYPE, &organization.id.to_string(), organization)
            .await?;
        Ok(organization.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_entity(ENTITY_TYPE, &id.to_string())
            .await
    }
}
