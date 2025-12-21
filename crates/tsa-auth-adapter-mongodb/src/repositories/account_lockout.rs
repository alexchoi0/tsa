use async_trait::async_trait;
use chrono::Utc;
use mongodb::{bson::doc, Collection, Database};
use tsa_auth_core::{AccountLockout, AccountLockoutRepository, Result, TsaError};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbAccountLockoutRepository {
    collection: Collection<AccountLockout>,
}

impl MongoDbAccountLockoutRepository {
    pub fn new(collection: Collection<AccountLockout>) -> Self {
        Self { collection }
    }

    pub fn from_database(db: &Database) -> Self {
        Self::new(db.collection::<AccountLockout>("account_lockouts"))
    }
}

#[async_trait]
impl AccountLockoutRepository for MongoDbAccountLockoutRepository {
    async fn create(&self, lockout: &AccountLockout) -> Result<AccountLockout> {
        self.collection
            .insert_one(lockout)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(lockout.clone())
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Option<AccountLockout>> {
        self.collection
            .find_one(doc! { "user_id": user_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn update(&self, lockout: &AccountLockout) -> Result<AccountLockout> {
        self.collection
            .replace_one(doc! { "id": lockout.id }, lockout)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(lockout.clone())
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

    async fn increment_failed_attempts(&self, user_id: Uuid) -> Result<AccountLockout> {
        let existing = self.find_by_user(user_id).await?;

        match existing {
            Some(lockout) => {
                let updated = AccountLockout {
                    failed_attempts: lockout.failed_attempts + 1,
                    updated_at: Utc::now(),
                    ..lockout
                };
                self.update(&updated).await
            }
            None => {
                let now = Utc::now();
                let lockout = AccountLockout {
                    id: Uuid::new_v4(),
                    user_id,
                    failed_attempts: 1,
                    locked_until: None,
                    last_failed_at: Some(now),
                    created_at: now,
                    updated_at: now,
                };
                self.create(&lockout).await
            }
        }
    }

    async fn reset_failed_attempts(&self, user_id: Uuid) -> Result<()> {
        self.delete_by_user(user_id).await
    }
}
