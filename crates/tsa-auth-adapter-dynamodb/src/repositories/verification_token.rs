use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use chrono::Utc;
use std::collections::HashMap;
use tsa_auth_core::{Result, TokenType, TsaError, VerificationToken, VerificationTokenRepository};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_VERIFICATION_TOKENS;

#[derive(Clone)]
pub struct DynamoDbVerificationTokenRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbVerificationTokenRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_VERIFICATION_TOKENS)
    }

    fn to_item(token: &VerificationToken) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(token.id.to_string()));
        item.insert(
            "user_id".to_string(),
            AttributeValue::S(token.user_id.to_string()),
        );
        item.insert(
            "token_hash".to_string(),
            AttributeValue::S(token.token_hash.clone()),
        );
        item.insert(
            "token_type".to_string(),
            AttributeValue::S(format!("{:?}", token.token_type)),
        );
        item.insert(
            "expires_at".to_string(),
            AttributeValue::S(token.expires_at.to_rfc3339()),
        );
        item.insert(
            "created_at".to_string(),
            AttributeValue::S(token.created_at.to_rfc3339()),
        );
        item.insert(
            "ttl".to_string(),
            AttributeValue::N(token.expires_at.timestamp().to_string()),
        );
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<VerificationToken> {
        let token_type_str = get_string(item, "token_type")?;
        let token_type = match token_type_str.as_str() {
            "EmailVerification" => TokenType::EmailVerification,
            "PasswordReset" => TokenType::PasswordReset,
            "MagicLink" => TokenType::MagicLink,
            "EmailOtp" => TokenType::EmailOtp,
            "PhoneOtp" => TokenType::PhoneOtp,
            _ => {
                return Err(TsaError::Database(format!(
                    "Invalid token type: {}",
                    token_type_str
                )))
            }
        };

        Ok(VerificationToken {
            id: get_uuid(item, "id")?,
            user_id: get_uuid(item, "user_id")?,
            token_hash: get_string(item, "token_hash")?,
            token_type,
            expires_at: get_datetime(item, "expires_at")?,
            created_at: get_datetime(item, "created_at")?,
        })
    }
}

#[async_trait]
impl VerificationTokenRepository for DynamoDbVerificationTokenRepository {
    async fn create(&self, token: &VerificationToken) -> Result<VerificationToken> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(token)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(token.clone())
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<VerificationToken>> {
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
