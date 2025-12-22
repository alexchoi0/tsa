use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use std::collections::HashMap;
use tsa_auth_core::{Result, TsaError, TwoFactor, TwoFactorRepository};
use uuid::Uuid;

use super::super::TABLE_TWO_FACTORS;
use super::utils::*;

#[derive(Clone)]
pub struct DynamoDbTwoFactorRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbTwoFactorRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_TWO_FACTORS)
    }

    fn to_item(two_factor: &TwoFactor) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert(
            "id".to_string(),
            AttributeValue::S(two_factor.id.to_string()),
        );
        item.insert(
            "user_id".to_string(),
            AttributeValue::S(two_factor.user_id.to_string()),
        );
        item.insert(
            "secret".to_string(),
            AttributeValue::S(two_factor.secret.clone()),
        );
        item.insert(
            "backup_codes".to_string(),
            string_vec_to_attr(&two_factor.backup_codes),
        );
        item.insert(
            "enabled".to_string(),
            AttributeValue::Bool(two_factor.enabled),
        );
        item.insert(
            "verified".to_string(),
            AttributeValue::Bool(two_factor.verified),
        );
        item.insert(
            "created_at".to_string(),
            AttributeValue::S(two_factor.created_at.to_rfc3339()),
        );
        item.insert(
            "updated_at".to_string(),
            AttributeValue::S(two_factor.updated_at.to_rfc3339()),
        );
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<TwoFactor> {
        Ok(TwoFactor {
            id: get_uuid(item, "id")?,
            user_id: get_uuid(item, "user_id")?,
            secret: get_string(item, "secret")?,
            backup_codes: get_string_vec(item, "backup_codes"),
            enabled: get_bool(item, "enabled")?,
            verified: get_bool(item, "verified")?,
            created_at: get_datetime(item, "created_at")?,
            updated_at: get_datetime(item, "updated_at")?,
        })
    }
}

#[async_trait]
impl TwoFactorRepository for DynamoDbTwoFactorRepository {
    async fn create(&self, two_factor: &TwoFactor) -> Result<TwoFactor> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(two_factor)))
            .condition_expression("attribute_not_exists(user_id)")
            .send()
            .await
            .map_err(|e| {
                if e.to_string().contains("ConditionalCheckFailedException") {
                    TsaError::TwoFactorAlreadyEnabled
                } else {
                    TsaError::Database(e.to_string())
                }
            })?;
        Ok(two_factor.clone())
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<TwoFactor>> {
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

    async fn update(&self, two_factor: &TwoFactor) -> Result<TwoFactor> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(two_factor)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(two_factor.clone())
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
        if let Some(two_factor) = self.find_by_user_id(user_id).await? {
            self.delete(two_factor.id).await?;
        }
        Ok(())
    }
}
