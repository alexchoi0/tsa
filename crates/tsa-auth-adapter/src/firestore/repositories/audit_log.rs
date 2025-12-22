use async_trait::async_trait;
use tsa_auth_core::{AuditAction, AuditLog, AuditLogRepository, Result};
use uuid::Uuid;

use super::super::{client::FirestoreClient, COLLECTION_AUDIT_LOGS};

#[derive(Clone)]
pub struct FirestoreAuditLogRepository {
    client: FirestoreClient,
}

impl FirestoreAuditLogRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AuditLogRepository for FirestoreAuditLogRepository {
    async fn create(&self, log: &AuditLog) -> Result<AuditLog> {
        self.client
            .create_document(COLLECTION_AUDIT_LOGS, &log.id.to_string(), log)
            .await?;
        Ok(log.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<AuditLog>> {
        self.client
            .get_document(COLLECTION_AUDIT_LOGS, &id.to_string())
            .await
    }

    async fn find_by_user(&self, user_id: Uuid, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let logs = self
            .client
            .find_all_by_field(COLLECTION_AUDIT_LOGS, "user_id", &user_id.to_string())
            .await?;
        Ok(logs
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn find_by_action(
        &self,
        action: AuditAction,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditLog>> {
        let action_str = serde_json::to_string(&action).unwrap_or_default();
        let action_str = action_str.trim_matches('"');
        let logs = self
            .client
            .find_all_by_field(COLLECTION_AUDIT_LOGS, "action", action_str)
            .await?;
        Ok(logs
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn find_by_ip(&self, ip_address: &str, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let logs = self
            .client
            .find_all_by_field(COLLECTION_AUDIT_LOGS, "ip_address", ip_address)
            .await?;
        Ok(logs
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn find_recent(&self, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let mut logs: Vec<AuditLog> = self.client.list_documents(COLLECTION_AUDIT_LOGS).await?;
        logs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(logs
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn find_failed(&self, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let logs: Vec<AuditLog> = self.client.list_documents(COLLECTION_AUDIT_LOGS).await?;
        let failed_logs: Vec<AuditLog> = logs.into_iter().filter(|log| !log.success).collect();
        Ok(failed_logs
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn count_by_user(&self, user_id: Uuid) -> Result<u64> {
        let logs: Vec<AuditLog> = self
            .client
            .find_all_by_field(COLLECTION_AUDIT_LOGS, "user_id", &user_id.to_string())
            .await?;
        Ok(logs.len() as u64)
    }

    async fn count_failed_by_user_since(
        &self,
        user_id: Uuid,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32> {
        let logs: Vec<AuditLog> = self
            .client
            .find_all_by_field(COLLECTION_AUDIT_LOGS, "user_id", &user_id.to_string())
            .await?;
        let count = logs
            .into_iter()
            .filter(|log| !log.success && log.created_at >= since)
            .count();
        Ok(count as u32)
    }

    async fn delete_older_than(&self, before: chrono::DateTime<chrono::Utc>) -> Result<u64> {
        let logs: Vec<AuditLog> = self.client.list_documents(COLLECTION_AUDIT_LOGS).await?;
        let mut count = 0u64;
        for log in logs {
            if log.created_at < before {
                self.client
                    .delete_document(COLLECTION_AUDIT_LOGS, &log.id.to_string())
                    .await?;
                count += 1;
            }
        }
        Ok(count)
    }
}
