use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::{bson::doc, Collection, Database};
use tsa_auth_core::{ImpersonationSession, ImpersonationSessionRepository, Result, TsaError};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbImpersonationSessionRepository {
    collection: Collection<ImpersonationSession>,
}

impl MongoDbImpersonationSessionRepository {
    pub fn new(collection: Collection<ImpersonationSession>) -> Self {
        Self { collection }
    }

    pub fn from_database(db: &Database) -> Self {
        Self::new(db.collection::<ImpersonationSession>("impersonation_sessions"))
    }
}

#[async_trait]
impl ImpersonationSessionRepository for MongoDbImpersonationSessionRepository {
    async fn create(&self, session: &ImpersonationSession) -> Result<ImpersonationSession> {
        self.collection
            .insert_one(session)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(session.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<ImpersonationSession>> {
        self.collection
            .find_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_session_id(&self, session_id: Uuid) -> Result<Option<ImpersonationSession>> {
        self.collection
            .find_one(doc! {
                "impersonation_session_id": session_id,
                "ended_at": null
            })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_active_by_admin(&self, admin_id: Uuid) -> Result<Vec<ImpersonationSession>> {
        let cursor = self
            .collection
            .find(doc! {
                "admin_id": admin_id,
                "ended_at": null
            })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        cursor
            .try_collect()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_target_user(&self, target_user_id: Uuid) -> Result<Vec<ImpersonationSession>> {
        let cursor = self
            .collection
            .find(doc! { "target_user_id": target_user_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        cursor
            .try_collect()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn end_session(
        &self,
        id: Uuid,
        ended_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<ImpersonationSession> {
        self.collection
            .update_one(doc! { "id": id }, doc! { "$set": { "ended_at": ended_at } })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        self.find_by_id(id).await?.ok_or(TsaError::SessionNotFound)
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.collection
            .delete_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }
}
