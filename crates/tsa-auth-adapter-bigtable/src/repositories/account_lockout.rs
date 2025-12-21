use async_trait::async_trait;
use chrono::Utc;
use tsa_auth_core::{AccountLockout, AccountLockoutRepository, Result};
use uuid::Uuid;

use crate::client::BigtableClient;

const ENTITY_TYPE: &str = "account_lockout";

#[derive(Clone)]
pub struct BigtableAccountLockoutRepository {
    client: BigtableClient,
}

impl BigtableAccountLockoutRepository {
    pub fn new(client: BigtableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AccountLockoutRepository for BigtableAccountLockoutRepository {
    async fn create(&self, lockout: &AccountLockout) -> Result<AccountLockout> {
        self.client
            .create_entity(ENTITY_TYPE, &lockout.id.to_string(), lockout)
            .await?;
        Ok(lockout.clone())
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Option<AccountLockout>> {
        self.client
            .find_by_field(ENTITY_TYPE, "user_id", &user_id.to_string())
            .await
    }

    async fn update(&self, lockout: &AccountLockout) -> Result<AccountLockout> {
        self.client
            .update_entity(ENTITY_TYPE, &lockout.id.to_string(), lockout)
            .await?;
        Ok(lockout.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_entity(ENTITY_TYPE, &id.to_string())
            .await
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        if let Some(lockout) = self.find_by_user(user_id).await? {
            self.delete(lockout.id).await?;
        }
        Ok(())
    }

    async fn increment_failed_attempts(&self, user_id: Uuid) -> Result<AccountLockout> {
        let mut lockout = if let Some(existing) = self.find_by_user(user_id).await? {
            existing
        } else {
            AccountLockout {
                id: Uuid::new_v4(),
                user_id,
                failed_attempts: 0,
                locked_until: None,
                last_failed_at: None,
                created_at: Utc::now(),
                updated_at: Utc::now(),
            }
        };

        lockout.failed_attempts += 1;
        lockout.last_failed_at = Some(Utc::now());
        lockout.updated_at = Utc::now();

        self.update(&lockout).await
    }

    async fn reset_failed_attempts(&self, user_id: Uuid) -> Result<()> {
        if let Some(mut lockout) = self.find_by_user(user_id).await? {
            lockout.failed_attempts = 0;
            lockout.locked_until = None;
            lockout.updated_at = Utc::now();
            self.update(&lockout).await?;
        }
        Ok(())
    }
}
