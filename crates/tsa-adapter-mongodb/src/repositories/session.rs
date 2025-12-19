use async_trait::async_trait;
use chrono::Utc;
use futures::TryStreamExt;
use mongodb::{bson::doc, Collection};
use tsa_core::{Result, Session, SessionRepository, TsaError};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbSessionRepository {
    collection: Collection<Session>,
}

impl MongoDbSessionRepository {
    pub fn new(collection: Collection<Session>) -> Self {
        Self { collection }
    }
}

#[async_trait]
impl SessionRepository for MongoDbSessionRepository {
    async fn create(&self, session: &Session) -> Result<Session> {
        self.collection
            .insert_one(session)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(session.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Session>> {
        self.collection
            .find_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>> {
        self.collection
            .find_one(doc! { "token_hash": token_hash })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Session>> {
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

    async fn update(&self, session: &Session) -> Result<Session> {
        self.collection
            .replace_one(doc! { "id": session.id }, session)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(session.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.collection
            .delete_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }

    async fn delete_by_user_id(&self, user_id: Uuid) -> Result<()> {
        self.collection
            .delete_many(doc! { "user_id": user_id })
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
