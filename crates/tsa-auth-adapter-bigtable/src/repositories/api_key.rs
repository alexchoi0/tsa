use async_trait::async_trait;
use chrono::Utc;
use tsa_auth_core::{ApiKey, ApiKeyRepository, Result};
use uuid::Uuid;

use crate::client::BigtableClient;

const ENTITY_TYPE: &str = "api_key";

#[derive(Clone)]
pub struct BigtableApiKeyRepository {
    client: BigtableClient,
}

impl BigtableApiKeyRepository {
    pub fn new(client: BigtableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ApiKeyRepository for BigtableApiKeyRepository {
    async fn create(&self, api_key: &ApiKey) -> Result<ApiKey> {
        self.client
            .create_entity(ENTITY_TYPE, &api_key.id.to_string(), api_key)
            .await?;
        Ok(api_key.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<ApiKey>> {
        self.client.get_entity(ENTITY_TYPE, &id.to_string()).await
    }

    async fn find_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        self.client
            .find_by_field(ENTITY_TYPE, "key_hash", key_hash)
            .await
    }

    async fn find_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>> {
        self.client
            .find_by_field(ENTITY_TYPE, "prefix", prefix)
            .await
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>> {
        self.client
            .find_all_by_field(ENTITY_TYPE, "user_id", &user_id.to_string())
            .await
    }

    async fn find_by_organization(&self, organization_id: Uuid) -> Result<Vec<ApiKey>> {
        self.client
            .find_all_by_field(ENTITY_TYPE, "organization_id", &organization_id.to_string())
            .await
    }

    async fn update(&self, api_key: &ApiKey) -> Result<ApiKey> {
        self.client
            .update_entity(ENTITY_TYPE, &api_key.id.to_string(), api_key)
            .await?;
        Ok(api_key.clone())
    }

    async fn update_last_used(&self, id: Uuid) -> Result<()> {
        if let Some(mut api_key) = self.find_by_id(id).await? {
            api_key.last_used_at = Some(Utc::now());
            self.update(&api_key).await?;
        }
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_entity(ENTITY_TYPE, &id.to_string())
            .await
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        let api_keys = self.find_by_user(user_id).await?;
        for api_key in api_keys {
            self.delete(api_key.id).await?;
        }
        Ok(())
    }
}
