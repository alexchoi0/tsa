use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use std::collections::HashMap;
use tsa_auth_core::{PasswordHistory, PasswordHistoryRepository, Result, TsaError};
use uuid::Uuid;

use super::super::TABLE_PASSWORD_HISTORY;
use super::utils::*;

#[derive(Clone)]
pub struct DynamoDbPasswordHistoryRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbPasswordHistoryRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_PASSWORD_HISTORY)
    }

    fn to_item(history: &PasswordHistory) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(history.id.to_string()));
        item.insert(
            "user_id".to_string(),
            AttributeValue::S(history.user_id.to_string()),
        );
        item.insert(
            "password_hash".to_string(),
            AttributeValue::S(history.password_hash.clone()),
        );
        item.insert(
            "created_at".to_string(),
            AttributeValue::S(history.created_at.to_rfc3339()),
        );
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<PasswordHistory> {
        Ok(PasswordHistory {
            id: get_uuid(item, "id")?,
            user_id: get_uuid(item, "user_id")?,
            password_hash: get_string(item, "password_hash")?,
            created_at: get_datetime(item, "created_at")?,
        })
    }
}

#[async_trait]
impl PasswordHistoryRepository for DynamoDbPasswordHistoryRepository {
    async fn create(&self, history: &PasswordHistory) -> Result<PasswordHistory> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(history)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(history.clone())
    }

    async fn find_by_user(&self, user_id: Uuid, limit: u32) -> Result<Vec<PasswordHistory>> {
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

        let mut entries: Vec<PasswordHistory> = result
            .items
            .unwrap_or_default()
            .iter()
            .filter_map(|item| Self::from_item(item).ok())
            .collect();

        entries.sort_by(|a, b| b.created_at.cmp(&a.created_at));
        entries.truncate(limit as usize);
        Ok(entries)
    }

    async fn delete_old_entries(&self, user_id: Uuid, keep_count: u32) -> Result<u64> {
        let all_entries = self.find_by_user(user_id, u32::MAX).await?;

        if all_entries.len() <= keep_count as usize {
            return Ok(0);
        }

        let to_delete: Vec<Uuid> = all_entries
            .into_iter()
            .skip(keep_count as usize)
            .map(|e| e.id)
            .collect();

        let count = to_delete.len() as u64;

        for id in to_delete {
            self.client
                .delete_item()
                .table_name(self.table_name())
                .key("id", AttributeValue::S(id.to_string()))
                .send()
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(count)
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        let entries = self.find_by_user(user_id, u32::MAX).await?;
        for entry in entries {
            self.client
                .delete_item()
                .table_name(self.table_name())
                .key("id", AttributeValue::S(entry.id.to_string()))
                .send()
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }
        Ok(())
    }
}
