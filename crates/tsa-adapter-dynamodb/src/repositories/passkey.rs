use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use base64::{engine::general_purpose::STANDARD, Engine};
use std::collections::HashMap;
use tsa_core::{Passkey, PasskeyRepository, Result, TsaError};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_PASSKEYS;

#[derive(Clone)]
pub struct DynamoDbPasskeyRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbPasskeyRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_PASSKEYS)
    }

    fn to_item(passkey: &Passkey) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(passkey.id.to_string()));
        item.insert("user_id".to_string(), AttributeValue::S(passkey.user_id.to_string()));
        item.insert("credential_id".to_string(), AttributeValue::B(passkey.credential_id.clone().into()));
        item.insert("credential_id_b64".to_string(), AttributeValue::S(STANDARD.encode(&passkey.credential_id)));
        item.insert("public_key".to_string(), AttributeValue::B(passkey.public_key.clone().into()));
        item.insert("counter".to_string(), AttributeValue::N(passkey.counter.to_string()));
        item.insert("name".to_string(), AttributeValue::S(passkey.name.clone()));
        if let Some(ref transports) = passkey.transports {
            item.insert("transports".to_string(), string_vec_to_attr(transports));
        }
        item.insert("created_at".to_string(), AttributeValue::S(passkey.created_at.to_rfc3339()));
        if let Some(ref last_used) = passkey.last_used_at {
            item.insert("last_used_at".to_string(), AttributeValue::S(last_used.to_rfc3339()));
        }
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<Passkey> {
        let transports = if item.contains_key("transports") {
            Some(get_string_vec(item, "transports"))
        } else {
            None
        };

        Ok(Passkey {
            id: get_uuid(item, "id")?,
            user_id: get_uuid(item, "user_id")?,
            credential_id: get_bytes(item, "credential_id")?,
            public_key: get_bytes(item, "public_key")?,
            counter: get_u32(item, "counter")?,
            name: get_string(item, "name")?,
            transports,
            created_at: get_datetime(item, "created_at")?,
            last_used_at: get_datetime_opt(item, "last_used_at")?,
        })
    }
}

#[async_trait]
impl PasskeyRepository for DynamoDbPasskeyRepository {
    async fn create(&self, passkey: &Passkey) -> Result<Passkey> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(passkey)))
            .condition_expression("attribute_not_exists(id)")
            .send()
            .await
            .map_err(|e| {
                if e.to_string().contains("ConditionalCheckFailedException") {
                    TsaError::PasskeyAlreadyRegistered
                } else {
                    TsaError::Database(e.to_string())
                }
            })?;
        Ok(passkey.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Passkey>> {
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

    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Passkey>> {
        let credential_id_b64 = STANDARD.encode(credential_id);
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("credential_id_b64-index")
            .key_condition_expression("credential_id_b64 = :cred_id")
            .expression_attribute_values(":cred_id", AttributeValue::S(credential_id_b64))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match result.items.and_then(|items| items.into_iter().next()) {
            Some(item) => Ok(Some(Self::from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Passkey>> {
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

    async fn update(&self, passkey: &Passkey) -> Result<Passkey> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(passkey)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(passkey.clone())
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
        let passkeys = self.find_by_user(user_id).await?;
        for passkey in passkeys {
            self.delete(passkey.id).await?;
        }
        Ok(())
    }
}
