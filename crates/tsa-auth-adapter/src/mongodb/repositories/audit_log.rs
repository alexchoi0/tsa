use async_trait::async_trait;
use futures::TryStreamExt;
use mongodb::{bson::doc, options::FindOptions, Collection, Database};
use tsa_auth_core::{AuditAction, AuditLog, AuditLogRepository, Result, TsaError};
use uuid::Uuid;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct AuditLogDocument {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub actor_id: Option<Uuid>,
    pub action: String,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub details: Option<serde_json::Value>,
    pub success: bool,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

impl From<&AuditLog> for AuditLogDocument {
    fn from(log: &AuditLog) -> Self {
        let action_str = serde_json::to_value(log.action)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "other".to_string());

        Self {
            id: log.id,
            user_id: log.user_id,
            actor_id: log.actor_id,
            action: action_str,
            ip_address: log.ip_address.clone(),
            user_agent: log.user_agent.clone(),
            resource_type: log.resource_type.clone(),
            resource_id: log.resource_id.clone(),
            details: log.details.clone(),
            success: log.success,
            error_message: log.error_message.clone(),
            created_at: log.created_at,
        }
    }
}

impl From<AuditLogDocument> for AuditLog {
    fn from(doc: AuditLogDocument) -> Self {
        let action: AuditAction = serde_json::from_value(serde_json::json!(doc.action))
            .unwrap_or(AuditAction::SigninFailed);

        Self {
            id: doc.id,
            user_id: doc.user_id,
            actor_id: doc.actor_id,
            action,
            ip_address: doc.ip_address,
            user_agent: doc.user_agent,
            resource_type: doc.resource_type,
            resource_id: doc.resource_id,
            details: doc.details,
            success: doc.success,
            error_message: doc.error_message,
            created_at: doc.created_at,
        }
    }
}

#[derive(Clone)]
pub struct MongoDbAuditLogRepository {
    collection: Collection<AuditLogDocument>,
}

impl MongoDbAuditLogRepository {
    pub fn from_database(db: &Database) -> Self {
        Self {
            collection: db.collection::<AuditLogDocument>("audit_logs"),
        }
    }
}

#[async_trait]
impl AuditLogRepository for MongoDbAuditLogRepository {
    async fn create(&self, log: &AuditLog) -> Result<AuditLog> {
        let doc = AuditLogDocument::from(log);
        self.collection
            .insert_one(&doc)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(log.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<AuditLog>> {
        self.collection
            .find_one(doc! { "id": id })
            .await
            .map(|opt| opt.map(Into::into))
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_user(&self, user_id: Uuid, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let options = FindOptions::builder()
            .sort(doc! { "created_at": -1 })
            .skip(offset as u64)
            .limit(limit as i64)
            .build();

        let cursor = self
            .collection
            .find(doc! { "user_id": user_id })
            .with_options(options)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        cursor
            .try_collect::<Vec<_>>()
            .await
            .map(|docs| docs.into_iter().map(Into::into).collect())
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_action(
        &self,
        action: AuditAction,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditLog>> {
        let action_str = serde_json::to_value(action)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "other".to_string());

        let options = FindOptions::builder()
            .sort(doc! { "created_at": -1 })
            .skip(offset as u64)
            .limit(limit as i64)
            .build();

        let cursor = self
            .collection
            .find(doc! { "action": action_str })
            .with_options(options)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        cursor
            .try_collect::<Vec<_>>()
            .await
            .map(|docs| docs.into_iter().map(Into::into).collect())
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_ip(&self, ip_address: &str, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let options = FindOptions::builder()
            .sort(doc! { "created_at": -1 })
            .skip(offset as u64)
            .limit(limit as i64)
            .build();

        let cursor = self
            .collection
            .find(doc! { "ip_address": ip_address })
            .with_options(options)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        cursor
            .try_collect::<Vec<_>>()
            .await
            .map(|docs| docs.into_iter().map(Into::into).collect())
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_recent(&self, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let options = FindOptions::builder()
            .sort(doc! { "created_at": -1 })
            .skip(offset as u64)
            .limit(limit as i64)
            .build();

        let cursor = self
            .collection
            .find(doc! {})
            .with_options(options)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        cursor
            .try_collect::<Vec<_>>()
            .await
            .map(|docs| docs.into_iter().map(Into::into).collect())
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_failed(&self, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let options = FindOptions::builder()
            .sort(doc! { "created_at": -1 })
            .skip(offset as u64)
            .limit(limit as i64)
            .build();

        let cursor = self
            .collection
            .find(doc! { "success": false })
            .with_options(options)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        cursor
            .try_collect::<Vec<_>>()
            .await
            .map(|docs| docs.into_iter().map(Into::into).collect())
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn count_by_user(&self, user_id: Uuid) -> Result<u64> {
        self.collection
            .count_documents(doc! { "user_id": user_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn count_failed_by_user_since(
        &self,
        user_id: Uuid,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32> {
        let count = self
            .collection
            .count_documents(doc! {
                "user_id": user_id,
                "success": false,
                "created_at": { "$gte": since }
            })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(count as u32)
    }

    async fn delete_older_than(&self, before: chrono::DateTime<chrono::Utc>) -> Result<u64> {
        let result = self
            .collection
            .delete_many(doc! { "created_at": { "$lt": before } })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(result.deleted_count)
    }
}
