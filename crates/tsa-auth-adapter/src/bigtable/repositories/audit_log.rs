use async_trait::async_trait;
use tsa_auth_core::{AuditAction, AuditLog, AuditLogRepository, Result};
use uuid::Uuid;

use super::super::client::BigtableClient;

const ENTITY_TYPE: &str = "audit_log";

#[derive(Clone)]
pub struct BigtableAuditLogRepository {
    client: BigtableClient,
}

impl BigtableAuditLogRepository {
    pub fn new(client: BigtableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl AuditLogRepository for BigtableAuditLogRepository {
    async fn create(&self, log: &AuditLog) -> Result<AuditLog> {
        self.client
            .create_entity(ENTITY_TYPE, &log.id.to_string(), log)
            .await?;
        Ok(log.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<AuditLog>> {
        self.client.get_entity(ENTITY_TYPE, &id.to_string()).await
    }

    async fn find_by_user(&self, user_id: Uuid, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let mut logs: Vec<AuditLog> = self
            .client
            .find_all_by_field(ENTITY_TYPE, "user_id", &user_id.to_string())
            .await?;
        logs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
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
        let all_logs: Vec<AuditLog> = self.client.list_entities(ENTITY_TYPE).await?;
        let mut filtered_logs: Vec<AuditLog> = all_logs
            .into_iter()
            .filter(|log| log.action == action)
            .collect();
        filtered_logs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(filtered_logs
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn find_by_ip(&self, ip_address: &str, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let mut logs: Vec<AuditLog> = self
            .client
            .find_all_by_field(ENTITY_TYPE, "ip_address", ip_address)
            .await?;
        logs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(logs
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn find_recent(&self, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let mut logs: Vec<AuditLog> = self.client.list_entities(ENTITY_TYPE).await?;
        logs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(logs
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn find_failed(&self, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let all_logs: Vec<AuditLog> = self.client.list_entities(ENTITY_TYPE).await?;
        let mut filtered_logs: Vec<AuditLog> =
            all_logs.into_iter().filter(|log| !log.success).collect();
        filtered_logs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(filtered_logs
            .into_iter()
            .skip(offset as usize)
            .take(limit as usize)
            .collect())
    }

    async fn count_by_user(&self, user_id: Uuid) -> Result<u64> {
        let logs = self
            .client
            .find_all_by_field::<AuditLog>(ENTITY_TYPE, "user_id", &user_id.to_string())
            .await?;
        Ok(logs.len() as u64)
    }

    async fn count_failed_by_user_since(
        &self,
        user_id: Uuid,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32> {
        let logs = self
            .client
            .find_all_by_field::<AuditLog>(ENTITY_TYPE, "user_id", &user_id.to_string())
            .await?;
        let count = logs
            .into_iter()
            .filter(|log| !log.success && log.created_at >= since)
            .count();
        Ok(count as u32)
    }

    async fn delete_older_than(&self, before: chrono::DateTime<chrono::Utc>) -> Result<u64> {
        let logs: Vec<AuditLog> = self.client.list_entities(ENTITY_TYPE).await?;
        let mut count = 0u64;
        for log in logs {
            if log.created_at < before {
                self.client
                    .delete_entity(ENTITY_TYPE, &log.id.to_string())
                    .await?;
                count += 1;
            }
        }
        Ok(count)
    }
}
