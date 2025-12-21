use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use chrono::Utc;
use std::collections::HashMap;
use tsa_auth_core::{Result, Session, SessionRepository, TsaError};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_SESSIONS;

#[derive(Clone)]
pub struct DynamoDbSessionRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbSessionRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_SESSIONS)
    }

    fn to_item(session: &Session) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(session.id.to_string()));
        item.insert("user_id".to_string(), AttributeValue::S(session.user_id.to_string()));
        item.insert("token_hash".to_string(), AttributeValue::S(session.token_hash.clone()));
        item.insert("expires_at".to_string(), AttributeValue::S(session.expires_at.to_rfc3339()));
        item.insert("created_at".to_string(), AttributeValue::S(session.created_at.to_rfc3339()));
        item.insert("ttl".to_string(), AttributeValue::N(session.expires_at.timestamp().to_string()));
        if let Some(ref ip) = session.ip_address {
            item.insert("ip_address".to_string(), AttributeValue::S(ip.clone()));
        }
        if let Some(ref ua) = session.user_agent {
            item.insert("user_agent".to_string(), AttributeValue::S(ua.clone()));
        }
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<Session> {
        Ok(Session {
            id: get_uuid(item, "id")?,
            user_id: get_uuid(item, "user_id")?,
            token_hash: get_string(item, "token_hash")?,
            expires_at: get_datetime(item, "expires_at")?,
            created_at: get_datetime(item, "created_at")?,
            ip_address: get_string_opt(item, "ip_address"),
            user_agent: get_string_opt(item, "user_agent"),
        })
    }
}

#[async_trait]
impl SessionRepository for DynamoDbSessionRepository {
    async fn create(&self, session: &Session) -> Result<Session> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(session)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(session.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Session>> {
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

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("token_hash-index")
            .key_condition_expression("token_hash = :token_hash")
            .expression_attribute_values(":token_hash", AttributeValue::S(token_hash.to_string()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match result.items.and_then(|items| items.into_iter().next()) {
            Some(item) => Ok(Some(Self::from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Session>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("user_id-index")
            .key_condition_expression("user_id = :user_id")
            .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
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

    async fn update(&self, session: &Session) -> Result<Session> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(session)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(session.clone())
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

    async fn delete_by_user_id(&self, user_id: Uuid) -> Result<()> {
        let sessions = self.find_by_user_id(user_id).await?;
        for session in sessions {
            self.delete(session.id).await?;
        }
        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64> {
        let now = Utc::now();
        let result = self
            .client
            .scan()
            .table_name(self.table_name())
            .filter_expression("expires_at < :now")
            .expression_attribute_values(":now", AttributeValue::S(now.to_rfc3339()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let items = result.items.unwrap_or_default();
        let count = items.len() as u64;

        for item in items {
            if let Ok(id) = get_uuid(&item, "id") {
                self.delete(id).await?;
            }
        }

        Ok(count)
    }
}
