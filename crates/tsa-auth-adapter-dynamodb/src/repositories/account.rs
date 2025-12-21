use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use std::collections::HashMap;
use tsa_auth_core::{Account, AccountRepository, Result, TsaError};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_ACCOUNTS;

#[derive(Clone)]
pub struct DynamoDbAccountRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbAccountRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_ACCOUNTS)
    }

    fn to_item(account: &Account) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(account.id.to_string()));
        item.insert(
            "user_id".to_string(),
            AttributeValue::S(account.user_id.to_string()),
        );
        item.insert(
            "provider".to_string(),
            AttributeValue::S(account.provider.clone()),
        );
        item.insert(
            "provider_account_id".to_string(),
            AttributeValue::S(account.provider_account_id.clone()),
        );
        item.insert(
            "provider_key".to_string(),
            AttributeValue::S(format!(
                "{}#{}",
                account.provider, account.provider_account_id
            )),
        );
        if let Some(ref token) = account.access_token {
            item.insert("access_token".to_string(), AttributeValue::S(token.clone()));
        }
        if let Some(ref token) = account.refresh_token {
            item.insert(
                "refresh_token".to_string(),
                AttributeValue::S(token.clone()),
            );
        }
        if let Some(ref expires) = account.expires_at {
            item.insert(
                "expires_at".to_string(),
                AttributeValue::S(expires.to_rfc3339()),
            );
        }
        item.insert(
            "created_at".to_string(),
            AttributeValue::S(account.created_at.to_rfc3339()),
        );
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<Account> {
        Ok(Account {
            id: get_uuid(item, "id")?,
            user_id: get_uuid(item, "user_id")?,
            provider: get_string(item, "provider")?,
            provider_account_id: get_string(item, "provider_account_id")?,
            access_token: get_string_opt(item, "access_token"),
            refresh_token: get_string_opt(item, "refresh_token"),
            expires_at: get_datetime_opt(item, "expires_at")?,
            created_at: get_datetime(item, "created_at")?,
        })
    }
}

#[async_trait]
impl AccountRepository for DynamoDbAccountRepository {
    async fn create(&self, account: &Account) -> Result<Account> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(account)))
            .condition_expression("attribute_not_exists(id)")
            .send()
            .await
            .map_err(|e| {
                if e.to_string().contains("ConditionalCheckFailedException") {
                    TsaError::AccountAlreadyLinked
                } else {
                    TsaError::Database(e.to_string())
                }
            })?;
        Ok(account.clone())
    }

    async fn find_by_provider(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> Result<Option<Account>> {
        let provider_key = format!("{}#{}", provider, provider_account_id);
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("provider_key-index")
            .key_condition_expression("provider_key = :pk")
            .expression_attribute_values(":pk", AttributeValue::S(provider_key))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match result.items.and_then(|items| items.into_iter().next()) {
            Some(item) => Ok(Some(Self::from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Account>> {
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
