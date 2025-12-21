use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use chrono::Utc;
use std::collections::HashMap;
use tsa_auth_core::{AccountLockout, AccountLockoutRepository, Result, TsaError};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_ACCOUNT_LOCKOUTS;

#[derive(Clone)]
pub struct DynamoDbAccountLockoutRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbAccountLockoutRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_ACCOUNT_LOCKOUTS)
    }

    fn to_item(lockout: &AccountLockout) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(lockout.id.to_string()));
        item.insert("user_id".to_string(), AttributeValue::S(lockout.user_id.to_string()));
        item.insert("failed_attempts".to_string(), AttributeValue::N(lockout.failed_attempts.to_string()));
        if let Some(ref locked_until) = lockout.locked_until {
            item.insert("locked_until".to_string(), AttributeValue::S(locked_until.to_rfc3339()));
        }
        if let Some(ref last_failed_at) = lockout.last_failed_at {
            item.insert("last_failed_at".to_string(), AttributeValue::S(last_failed_at.to_rfc3339()));
        }
        item.insert("created_at".to_string(), AttributeValue::S(lockout.created_at.to_rfc3339()));
        item.insert("updated_at".to_string(), AttributeValue::S(lockout.updated_at.to_rfc3339()));
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<AccountLockout> {
        Ok(AccountLockout {
            id: get_uuid(item, "id")?,
            user_id: get_uuid(item, "user_id")?,
            failed_attempts: get_u32(item, "failed_attempts")?,
            locked_until: get_datetime_opt(item, "locked_until")?,
            last_failed_at: get_datetime_opt(item, "last_failed_at")?,
            created_at: get_datetime(item, "created_at")?,
            updated_at: get_datetime(item, "updated_at")?,
        })
    }
}

#[async_trait]
impl AccountLockoutRepository for DynamoDbAccountLockoutRepository {
    async fn create(&self, lockout: &AccountLockout) -> Result<AccountLockout> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(lockout)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(lockout.clone())
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Option<AccountLockout>> {
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

        match result.items.and_then(|items| items.into_iter().next()) {
            Some(item) => Ok(Some(Self::from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn update(&self, lockout: &AccountLockout) -> Result<AccountLockout> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(lockout)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(lockout.clone())
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

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        if let Some(lockout) = self.find_by_user(user_id).await? {
            self.delete(lockout.id).await?;
        }
        Ok(())
    }

    async fn increment_failed_attempts(&self, user_id: Uuid) -> Result<AccountLockout> {
        let existing = self.find_by_user(user_id).await?;

        match existing {
            Some(lockout) => {
                let updated = AccountLockout {
                    failed_attempts: lockout.failed_attempts + 1,
                    updated_at: Utc::now(),
                    ..lockout
                };
                self.update(&updated).await
            }
            None => {
                let now = Utc::now();
                let lockout = AccountLockout {
                    id: Uuid::new_v4(),
                    user_id,
                    failed_attempts: 1,
                    locked_until: None,
                    last_failed_at: Some(now),
                    created_at: now,
                    updated_at: now,
                };
                self.create(&lockout).await
            }
        }
    }

    async fn reset_failed_attempts(&self, user_id: Uuid) -> Result<()> {
        self.delete_by_user(user_id).await
    }
}
