use async_trait::async_trait;
use chrono::Utc;
use tsa_core::{ApiKey, ApiKeyRepository, Result};
use uuid::Uuid;

use crate::{client::FirestoreClient, COLLECTION_API_KEYS};

#[derive(Clone)]
pub struct FirestoreApiKeyRepository {
    client: FirestoreClient,
}

impl FirestoreApiKeyRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ApiKeyRepository for FirestoreApiKeyRepository {
    async fn create(&self, api_key: &ApiKey) -> Result<ApiKey> {
        self.client
            .create_document(COLLECTION_API_KEYS, &api_key.id.to_string(), api_key)
            .await?;
        Ok(api_key.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<ApiKey>> {
        self.client
            .get_document(COLLECTION_API_KEYS, &id.to_string())
            .await
    }

    async fn find_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        self.client
            .find_by_field(COLLECTION_API_KEYS, "key_hash", key_hash)
            .await
    }

    async fn find_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>> {
        self.client
            .find_by_field(COLLECTION_API_KEYS, "prefix", prefix)
            .await
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>> {
        self.client
            .find_all_by_field(COLLECTION_API_KEYS, "user_id", &user_id.to_string())
            .await
    }

    async fn find_by_organization(&self, organization_id: Uuid) -> Result<Vec<ApiKey>> {
        self.client
            .find_all_by_field(
                COLLECTION_API_KEYS,
                "organization_id",
                &organization_id.to_string(),
            )
            .await
    }

    async fn update(&self, api_key: &ApiKey) -> Result<ApiKey> {
        self.client
            .update_document(COLLECTION_API_KEYS, &api_key.id.to_string(), api_key)
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
            .delete_document(COLLECTION_API_KEYS, &id.to_string())
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
