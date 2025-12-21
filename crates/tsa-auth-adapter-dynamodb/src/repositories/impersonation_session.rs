use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use std::collections::HashMap;
use tsa_auth_core::{ImpersonationSession, ImpersonationSessionRepository, Result, TsaError};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_IMPERSONATION_SESSIONS;

#[derive(Clone)]
pub struct DynamoDbImpersonationSessionRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbImpersonationSessionRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_IMPERSONATION_SESSIONS)
    }

    fn to_item(session: &ImpersonationSession) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(session.id.to_string()));
        item.insert("admin_id".to_string(), AttributeValue::S(session.admin_id.to_string()));
        item.insert("target_user_id".to_string(), AttributeValue::S(session.target_user_id.to_string()));
        item.insert("original_session_id".to_string(), AttributeValue::S(session.original_session_id.to_string()));
        item.insert("impersonation_session_id".to_string(), AttributeValue::S(session.impersonation_session_id.to_string()));
        if let Some(ref reason) = session.reason {
            item.insert("reason".to_string(), AttributeValue::S(reason.clone()));
        }
        item.insert("started_at".to_string(), AttributeValue::S(session.started_at.to_rfc3339()));
        if let Some(ref ended_at) = session.ended_at {
            item.insert("ended_at".to_string(), AttributeValue::S(ended_at.to_rfc3339()));
        }
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<ImpersonationSession> {
        Ok(ImpersonationSession {
            id: get_uuid(item, "id")?,
            admin_id: get_uuid(item, "admin_id")?,
            target_user_id: get_uuid(item, "target_user_id")?,
            original_session_id: get_uuid(item, "original_session_id")?,
            impersonation_session_id: get_uuid(item, "impersonation_session_id")?,
            reason: get_string_opt(item, "reason"),
            started_at: get_datetime(item, "started_at")?,
            ended_at: get_datetime_opt(item, "ended_at")?,
        })
    }
}

#[async_trait]
impl ImpersonationSessionRepository for DynamoDbImpersonationSessionRepository {
    async fn create(&self, session: &ImpersonationSession) -> Result<ImpersonationSession> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(session)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(session.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<ImpersonationSession>> {
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

    async fn find_by_session_id(&self, session_id: Uuid) -> Result<Option<ImpersonationSession>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("impersonation_session_id-index")
            .key_condition_expression("impersonation_session_id = :sid")
            .filter_expression("attribute_not_exists(ended_at)")
            .expression_attribute_values(":sid", AttributeValue::S(session_id.to_string()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match result.items.and_then(|items| items.into_iter().next()) {
            Some(item) => {
                let session = Self::from_item(&item)?;
                if session.ended_at.is_none() {
                    Ok(Some(session))
                } else {
                    Ok(None)
                }
            }
            None => Ok(None),
        }
    }

    async fn find_active_by_admin(&self, admin_id: Uuid) -> Result<Vec<ImpersonationSession>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("admin_id-index")
            .key_condition_expression("admin_id = :admin_id")
            .expression_attribute_values(":admin_id", AttributeValue::S(admin_id.to_string()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(result
            .items
            .unwrap_or_default()
            .iter()
            .filter_map(|item| Self::from_item(item).ok())
            .filter(|s| s.ended_at.is_none())
            .collect())
    }

    async fn find_by_target_user(&self, target_user_id: Uuid) -> Result<Vec<ImpersonationSession>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("target_user_id-index")
            .key_condition_expression("target_user_id = :target_user_id")
            .expression_attribute_values(":target_user_id", AttributeValue::S(target_user_id.to_string()))
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

    async fn end_session(
        &self,
        id: Uuid,
        ended_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<ImpersonationSession> {
        self.client
            .update_item()
            .table_name(self.table_name())
            .key("id", AttributeValue::S(id.to_string()))
            .update_expression("SET ended_at = :ended_at")
            .expression_attribute_values(":ended_at", AttributeValue::S(ended_at.to_rfc3339()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        self.find_by_id(id)
            .await?
            .ok_or(TsaError::SessionNotFound)
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_item()
            .table_name(self.table_name())
            .key("id", AttributeValue::S(id.to_string()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }
}
