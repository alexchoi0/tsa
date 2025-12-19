use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use chrono::Utc;
use std::collections::HashMap;
use tsa_core::{ApiKey, ApiKeyRepository, Result, TsaError};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_API_KEYS;

#[derive(Clone)]
pub struct DynamoDbApiKeyRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbApiKeyRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_API_KEYS)
    }

    fn to_item(api_key: &ApiKey) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(api_key.id.to_string()));
        item.insert("user_id".to_string(), AttributeValue::S(api_key.user_id.to_string()));
        if let Some(ref org_id) = api_key.organization_id {
            item.insert("organization_id".to_string(), AttributeValue::S(org_id.to_string()));
        }
        item.insert("name".to_string(), AttributeValue::S(api_key.name.clone()));
        item.insert("key_hash".to_string(), AttributeValue::S(api_key.key_hash.clone()));
        item.insert("prefix".to_string(), AttributeValue::S(api_key.prefix.clone()));
        item.insert("scopes".to_string(), string_vec_to_attr(&api_key.scopes));
        if let Some(ref expires) = api_key.expires_at {
            item.insert("expires_at".to_string(), AttributeValue::S(expires.to_rfc3339()));
        }
        if let Some(ref last_used) = api_key.last_used_at {
            item.insert("last_used_at".to_string(), AttributeValue::S(last_used.to_rfc3339()));
        }
        item.insert("created_at".to_string(), AttributeValue::S(api_key.created_at.to_rfc3339()));
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<ApiKey> {
        Ok(ApiKey {
            id: get_uuid(item, "id")?,
            user_id: get_uuid(item, "user_id")?,
            organization_id: get_uuid_opt(item, "organization_id")?,
            name: get_string(item, "name")?,
            key_hash: get_string(item, "key_hash")?,
            prefix: get_string(item, "prefix")?,
            scopes: get_string_vec(item, "scopes"),
            expires_at: get_datetime_opt(item, "expires_at")?,
            last_used_at: get_datetime_opt(item, "last_used_at")?,
            created_at: get_datetime(item, "created_at")?,
        })
    }
}

#[async_trait]
impl ApiKeyRepository for DynamoDbApiKeyRepository {
    async fn create(&self, api_key: &ApiKey) -> Result<ApiKey> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(api_key)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(api_key.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<ApiKey>> {
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

    async fn find_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("key_hash-index")
            .key_condition_expression("key_hash = :key_hash")
            .expression_attribute_values(":key_hash", AttributeValue::S(key_hash.to_string()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match result.items.and_then(|items| items.into_iter().next()) {
            Some(item) => Ok(Some(Self::from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn find_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("prefix-index")
            .key_condition_expression("prefix = :prefix")
            .expression_attribute_values(":prefix", AttributeValue::S(prefix.to_string()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match result.items.and_then(|items| items.into_iter().next()) {
            Some(item) => Ok(Some(Self::from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>> {
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

    async fn find_by_organization(&self, organization_id: Uuid) -> Result<Vec<ApiKey>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("organization_id-index")
            .key_condition_expression("organization_id = :org_id")
            .expression_attribute_values(":org_id", AttributeValue::S(organization_id.to_string()))
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

    async fn update(&self, api_key: &ApiKey) -> Result<ApiKey> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(api_key)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(api_key.clone())
    }

    async fn update_last_used(&self, id: Uuid) -> Result<()> {
        self.client
            .update_item()
            .table_name(self.table_name())
            .key("id", AttributeValue::S(id.to_string()))
            .update_expression("SET last_used_at = :now")
            .expression_attribute_values(":now", AttributeValue::S(Utc::now().to_rfc3339()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
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
        let api_keys = self.find_by_user(user_id).await?;
        for api_key in api_keys {
            self.delete(api_key.id).await?;
        }
        Ok(())
    }
}
