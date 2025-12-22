use async_trait::async_trait;
use chrono::Utc;
use futures::TryStreamExt;
use mongodb::{bson::doc, Collection};
use tsa_auth_core::{ApiKey, ApiKeyRepository, Result, TsaError};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbApiKeyRepository {
    collection: Collection<ApiKey>,
}

impl MongoDbApiKeyRepository {
    pub fn new(collection: Collection<ApiKey>) -> Self {
        Self { collection }
    }
}

#[async_trait]
impl ApiKeyRepository for MongoDbApiKeyRepository {
    async fn create(&self, api_key: &ApiKey) -> Result<ApiKey> {
        self.collection
            .insert_one(api_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(api_key.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<ApiKey>> {
        self.collection
            .find_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        self.collection
            .find_one(doc! { "key_hash": key_hash })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>> {
        self.collection
            .find_one(doc! { "prefix": prefix })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>> {
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

    async fn find_by_organization(&self, organization_id: Uuid) -> Result<Vec<ApiKey>> {
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

    async fn update(&self, api_key: &ApiKey) -> Result<ApiKey> {
        self.collection
            .replace_one(doc! { "id": api_key.id }, api_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(api_key.clone())
    }

    async fn update_last_used(&self, id: Uuid) -> Result<()> {
        self.collection
            .update_one(
                doc! { "id": id },
                doc! { "$set": { "last_used_at": Utc::now() } },
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

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        self.collection
            .delete_many(doc! { "user_id": user_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }
}
