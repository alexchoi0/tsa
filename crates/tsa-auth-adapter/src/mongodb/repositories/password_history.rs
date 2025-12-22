use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::{bson::doc, options::FindOptions, Collection, Database};
use tsa_auth_core::{PasswordHistory, PasswordHistoryRepository, Result, TsaError};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbPasswordHistoryRepository {
    collection: Collection<PasswordHistory>,
}

impl MongoDbPasswordHistoryRepository {
    pub fn new(collection: Collection<PasswordHistory>) -> Self {
        Self { collection }
    }

    pub fn from_database(db: &Database) -> Self {
        Self::new(db.collection::<PasswordHistory>("password_history"))
    }
}

#[async_trait]
impl PasswordHistoryRepository for MongoDbPasswordHistoryRepository {
    async fn create(&self, history: &PasswordHistory) -> Result<PasswordHistory> {
        self.collection
            .insert_one(history)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(history.clone())
    }

    async fn find_by_user(&self, user_id: Uuid, limit: u32) -> Result<Vec<PasswordHistory>> {
        let options = FindOptions::builder()
            .sort(doc! { "created_at": -1 })
            .limit(limit as i64)
            .build();

        let cursor = self
            .collection
            .find(doc! { "user_id": user_id })
            .with_options(options)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        cursor
            .try_collect()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn delete_old_entries(&self, user_id: Uuid, keep_count: u32) -> Result<u64> {
        let all_entries = self.find_by_user(user_id, u32::MAX).await?;

        if all_entries.len() <= keep_count as usize {
            return Ok(0);
        }

        let to_delete: Vec<Uuid> = all_entries
            .into_iter()
            .skip(keep_count as usize)
            .map(|e| e.id)
            .collect();

        let count = to_delete.len() as u64;

        for id in to_delete {
            self.collection
                .delete_one(doc! { "id": id })
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(count)
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        self.collection
            .delete_many(doc! { "user_id": user_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }
}
