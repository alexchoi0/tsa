use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use std::collections::HashMap;
use tsa_auth_core::{AuditAction, AuditLog, AuditLogRepository, Result, TsaError};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_AUDIT_LOGS;

#[derive(Clone)]
pub struct DynamoDbAuditLogRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbAuditLogRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_AUDIT_LOGS)
    }

    fn to_item(log: &AuditLog) -> HashMap<String, AttributeValue> {
        let action_str = serde_json::to_value(log.action)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "other".to_string());

        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(log.id.to_string()));
        if let Some(user_id) = log.user_id {
            item.insert(
                "user_id".to_string(),
                AttributeValue::S(user_id.to_string()),
            );
        }
        if let Some(actor_id) = log.actor_id {
            item.insert(
                "actor_id".to_string(),
                AttributeValue::S(actor_id.to_string()),
            );
        }
        item.insert("action".to_string(), AttributeValue::S(action_str));
        if let Some(ref ip) = log.ip_address {
            item.insert("ip_address".to_string(), AttributeValue::S(ip.clone()));
        }
        if let Some(ref ua) = log.user_agent {
            item.insert("user_agent".to_string(), AttributeValue::S(ua.clone()));
        }
        if let Some(ref rt) = log.resource_type {
            item.insert("resource_type".to_string(), AttributeValue::S(rt.clone()));
        }
        if let Some(ref ri) = log.resource_id {
            item.insert("resource_id".to_string(), AttributeValue::S(ri.clone()));
        }
        if let Some(ref details) = log.details {
            item.insert(
                "details".to_string(),
                AttributeValue::S(details.to_string()),
            );
        }
        item.insert("success".to_string(), AttributeValue::Bool(log.success));
        if let Some(ref err) = log.error_message {
            item.insert("error_message".to_string(), AttributeValue::S(err.clone()));
        }
        item.insert(
            "created_at".to_string(),
            AttributeValue::S(log.created_at.to_rfc3339()),
        );
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<AuditLog> {
        let action_str = get_string(item, "action")?;
        let action: AuditAction = serde_json::from_value(serde_json::json!(action_str))
            .unwrap_or(AuditAction::SigninFailed);

        let details = get_string_opt(item, "details").and_then(|s| serde_json::from_str(&s).ok());

        Ok(AuditLog {
            id: get_uuid(item, "id")?,
            user_id: get_uuid_opt(item, "user_id")?,
            actor_id: get_uuid_opt(item, "actor_id")?,
            action,
            ip_address: get_string_opt(item, "ip_address"),
            user_agent: get_string_opt(item, "user_agent"),
            resource_type: get_string_opt(item, "resource_type"),
            resource_id: get_string_opt(item, "resource_id"),
            details,
            success: get_bool(item, "success")?,
            error_message: get_string_opt(item, "error_message"),
            created_at: get_datetime(item, "created_at")?,
        })
    }
}

#[async_trait]
impl AuditLogRepository for DynamoDbAuditLogRepository {
    async fn create(&self, log: &AuditLog) -> Result<AuditLog> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(log)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(log.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<AuditLog>> {
        let result = self
            .client
            .get_item()
            .table_name(self.table_name())
            .key("id", AttributeValue::S(id.to_string()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match result.item {
            Some(item) => Ok(Some(Self::from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn find_by_user(&self, user_id: Uuid, limit: u32, _offset: u32) -> Result<Vec<AuditLog>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("user_id-index")
            .key_condition_expression("user_id = :user_id")
            .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
            .limit(limit as i32)
            .scan_index_forward(false)
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        result
            .items
            .unwrap_or_default()
            .iter()
            .map(Self::from_item)
            .collect()
    }

    async fn find_by_action(
        &self,
        action: AuditAction,
        limit: u32,
        _offset: u32,
    ) -> Result<Vec<AuditLog>> {
        let action_str = serde_json::to_value(action)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_else(|| "other".to_string());

        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("action-index")
            .key_condition_expression("action = :action")
            .expression_attribute_values(":action", AttributeValue::S(action_str))
            .limit(limit as i32)
            .scan_index_forward(false)
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        result
            .items
            .unwrap_or_default()
            .iter()
            .map(Self::from_item)
            .collect()
    }

    async fn find_by_ip(
        &self,
        ip_address: &str,
        limit: u32,
        _offset: u32,
    ) -> Result<Vec<AuditLog>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("ip_address-index")
            .key_condition_expression("ip_address = :ip")
            .expression_attribute_values(":ip", AttributeValue::S(ip_address.to_string()))
            .limit(limit as i32)
            .scan_index_forward(false)
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        result
            .items
            .unwrap_or_default()
            .iter()
            .map(Self::from_item)
            .collect()
    }

    async fn find_recent(&self, limit: u32, _offset: u32) -> Result<Vec<AuditLog>> {
        let result = self
            .client
            .scan()
            .table_name(self.table_name())
            .limit(limit as i32)
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut logs: Vec<AuditLog> = result
            .items
            .unwrap_or_default()
            .iter()
            .filter_map(|item| Self::from_item(item).ok())
            .collect();

        logs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(logs)
    }

    async fn find_failed(&self, limit: u32, _offset: u32) -> Result<Vec<AuditLog>> {
        let result = self
            .client
            .scan()
            .table_name(self.table_name())
            .filter_expression("success = :success")
            .expression_attribute_values(":success", AttributeValue::Bool(false))
            .limit(limit as i32)
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut logs: Vec<AuditLog> = result
            .items
            .unwrap_or_default()
            .iter()
            .filter_map(|item| Self::from_item(item).ok())
            .collect();

        logs.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        Ok(logs)
    }

    async fn count_by_user(&self, user_id: Uuid) -> Result<u64> {
        let logs = self.find_by_user(user_id, u32::MAX, 0).await?;
        Ok(logs.len() as u64)
    }

    async fn count_failed_by_user_since(
        &self,
        user_id: Uuid,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("user_id-index")
            .key_condition_expression("user_id = :user_id")
            .filter_expression("success = :success AND created_at >= :since")
            .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
            .expression_attribute_values(":success", AttributeValue::Bool(false))
            .expression_attribute_values(":since", AttributeValue::S(since.to_rfc3339()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(result.items.unwrap_or_default().len() as u32)
    }

    async fn delete_older_than(&self, before: chrono::DateTime<chrono::Utc>) -> Result<u64> {
        let result = self
            .client
            .scan()
            .table_name(self.table_name())
            .filter_expression("created_at < :before")
            .expression_attribute_values(":before", AttributeValue::S(before.to_rfc3339()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let items = result.items.unwrap_or_default();
        let count = items.len() as u64;

        for item in items {
            if let Some(id) = item.get("id").and_then(|v| v.as_s().ok()) {
                self.client
                    .delete_item()
                    .table_name(self.table_name())
                    .key("id", AttributeValue::S(id.clone()))
                    .send()
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
            }
        }

        Ok(count)
    }
}
