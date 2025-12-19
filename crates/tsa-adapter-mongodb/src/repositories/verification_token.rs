use async_trait::async_trait;
use chrono::Utc;
use mongodb::{bson::doc, Collection};
use tsa_core::{Result, TsaError, VerificationToken, VerificationTokenRepository};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbVerificationTokenRepository {
    collection: Collection<VerificationToken>,
}

impl MongoDbVerificationTokenRepository {
    pub fn new(collection: Collection<VerificationToken>) -> Self {
        Self { collection }
    }
}

#[async_trait]
impl VerificationTokenRepository for MongoDbVerificationTokenRepository {
    async fn create(&self, token: &VerificationToken) -> Result<VerificationToken> {
        self.collection
            .insert_one(token)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(token.clone())
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<VerificationToken>> {
        self.collection
            .find_one(doc! { "token_hash": token_hash })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
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
