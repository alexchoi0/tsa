use async_trait::async_trait;
use chrono::Utc;
use tsa_auth_core::{AccountLockout, AccountLockoutRepository, Result};
use uuid::Uuid;

use crate::{client::FirestoreClient, COLLECTION_ACCOUNT_LOCKOUTS};

#[derive(Clone)]
pub struct FirestoreAccountLockoutRepository {
    client: FirestoreClient,
}

impl FirestoreAccountLockoutRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AccountLockoutRepository for FirestoreAccountLockoutRepository {
    async fn create(&self, lockout: &AccountLockout) -> Result<AccountLockout> {
        self.client
            .create_document(
                COLLECTION_ACCOUNT_LOCKOUTS,
                &lockout.id.to_string(),
                lockout,
            )
            .await?;
        Ok(lockout.clone())
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Option<AccountLockout>> {
        self.client
            .find_by_field(COLLECTION_ACCOUNT_LOCKOUTS, "user_id", &user_id.to_string())
            .await
    }

    async fn update(&self, lockout: &AccountLockout) -> Result<AccountLockout> {
        self.client
            .update_document(
                COLLECTION_ACCOUNT_LOCKOUTS,
                &lockout.id.to_string(),
                lockout,
            )
            .await?;
        Ok(lockout.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_document(COLLECTION_ACCOUNT_LOCKOUTS, &id.to_string())
            .await
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        if let Some(lockout) = self.find_by_user(user_id).await? {
            self.delete(lockout.id).await?;
        }
        Ok(())
    }

    async fn increment_failed_attempts(&self, user_id: Uuid) -> Result<AccountLockout> {
        if let Some(mut lockout) = self.find_by_user(user_id).await? {
            lockout.failed_attempts += 1;
            lockout.last_failed_at = Some(Utc::now());
            lockout.updated_at = Utc::now();
            self.update(&lockout).await
        } else {
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

    async fn reset_failed_attempts(&self, user_id: Uuid) -> Result<()> {
        if let Some(mut lockout) = self.find_by_user(user_id).await? {
            lockout.failed_attempts = 0;
            lockout.locked_until = None;
            lockout.last_failed_at = None;
            lockout.updated_at = Utc::now();
            self.update(&lockout).await?;
        }
        Ok(())
    }
}
