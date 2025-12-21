use async_trait::async_trait;
use tsa_auth_core::{PasswordHistory, PasswordHistoryRepository, Result};
use uuid::Uuid;

use crate::client::BigtableClient;

const ENTITY_TYPE: &str = "password_history";

#[derive(Clone)]
pub struct BigtablePasswordHistoryRepository {
    client: BigtableClient,
}

impl BigtablePasswordHistoryRepository {
    pub fn new(client: BigtableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PasswordHistoryRepository for BigtablePasswordHistoryRepository {
    async fn create(&self, history: &PasswordHistory) -> Result<PasswordHistory> {
        self.client
            .create_entity(ENTITY_TYPE, &history.id.to_string(), history)
            .await?;
        Ok(history.clone())
    }

    async fn find_by_user(&self, user_id: Uuid, limit: u32) -> Result<Vec<PasswordHistory>> {
        let mut histories: Vec<PasswordHistory> = self
            .client
            .find_all_by_field(ENTITY_TYPE, "user_id", &user_id.to_string())
            .await?;
        histories.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(histories.into_iter().take(limit as usize).collect())
    }

    async fn delete_old_entries(&self, user_id: Uuid, keep_count: u32) -> Result<u64> {
        let mut histories = self
            .client
            .find_all_by_field::<PasswordHistory>(ENTITY_TYPE, "user_id", &user_id.to_string())
            .await?;
        histories.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        let to_delete = histories.into_iter().skip(keep_count as usize);
        let mut count = 0u64;

        for history in to_delete {
            self.client
                .delete_entity(ENTITY_TYPE, &history.id.to_string())
                .await?;
            count += 1;
        }

        Ok(count)
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        let histories = self
            .client
            .find_all_by_field::<PasswordHistory>(ENTITY_TYPE, "user_id", &user_id.to_string())
            .await?;
        for history in histories {
            self.client
                .delete_entity(ENTITY_TYPE, &history.id.to_string())
                .await?;
        }
        Ok(())
    }
}
