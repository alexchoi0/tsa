use async_trait::async_trait;
use tsa_auth_core::{PasswordHistory, PasswordHistoryRepository, Result};
use uuid::Uuid;

use crate::{client::FirestoreClient, COLLECTION_PASSWORD_HISTORY};

#[derive(Clone)]
pub struct FirestorePasswordHistoryRepository {
    client: FirestoreClient,
}

impl FirestorePasswordHistoryRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PasswordHistoryRepository for FirestorePasswordHistoryRepository {
    async fn create(&self, history: &PasswordHistory) -> Result<PasswordHistory> {
        self.client
            .create_document(
                COLLECTION_PASSWORD_HISTORY,
                &history.id.to_string(),
                history,
            )
            .await?;
        Ok(history.clone())
    }

    async fn find_by_user(&self, user_id: Uuid, limit: u32) -> Result<Vec<PasswordHistory>> {
        let mut histories: Vec<PasswordHistory> = self
            .client
            .find_all_by_field(COLLECTION_PASSWORD_HISTORY, "user_id", &user_id.to_string())
            .await?;
        histories.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(histories.into_iter().take(limit as usize).collect())
    }

    async fn delete_old_entries(&self, user_id: Uuid, keep_count: u32) -> Result<u64> {
        let mut histories: Vec<PasswordHistory> = self
            .client
            .find_all_by_field(COLLECTION_PASSWORD_HISTORY, "user_id", &user_id.to_string())
            .await?;
        histories.sort_by(|a, b| b.created_at.cmp(&a.created_at));

        let to_delete: Vec<PasswordHistory> =
            histories.into_iter().skip(keep_count as usize).collect();

        let mut count = 0u64;
        for history in to_delete {
            self.client
                .delete_document(COLLECTION_PASSWORD_HISTORY, &history.id.to_string())
                .await?;
            count += 1;
        }

        Ok(count)
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        let histories: Vec<PasswordHistory> = self
            .client
            .find_all_by_field(COLLECTION_PASSWORD_HISTORY, "user_id", &user_id.to_string())
            .await?;
        for history in histories {
            self.client
                .delete_document(COLLECTION_PASSWORD_HISTORY, &history.id.to_string())
                .await?;
        }
        Ok(())
    }
}
