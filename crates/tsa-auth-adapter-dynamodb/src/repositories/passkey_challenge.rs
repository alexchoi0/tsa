use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use std::collections::HashMap;
use tsa_auth_core::{PasskeyChallenge, PasskeyChallengeRepository, PasskeyChallengeType, Result, TsaError};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_PASSKEY_CHALLENGES;

#[derive(Clone)]
pub struct DynamoDbPasskeyChallengeRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbPasskeyChallengeRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_PASSKEY_CHALLENGES)
    }

    fn to_item(challenge: &PasskeyChallenge) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(challenge.id.to_string()));
        if let Some(ref user_id) = challenge.user_id {
            item.insert("user_id".to_string(), AttributeValue::S(user_id.to_string()));
        }
        item.insert("challenge".to_string(), AttributeValue::B(challenge.challenge.clone().into()));
        item.insert("challenge_b64".to_string(), AttributeValue::S(STANDARD.encode(&challenge.challenge)));
        item.insert("challenge_type".to_string(), AttributeValue::S(format!("{:?}", challenge.challenge_type)));
        item.insert("state".to_string(), AttributeValue::B(challenge.state.clone().into()));
        item.insert("expires_at".to_string(), AttributeValue::S(challenge.expires_at.to_rfc3339()));
        item.insert("created_at".to_string(), AttributeValue::S(challenge.created_at.to_rfc3339()));
        item.insert("ttl".to_string(), AttributeValue::N(challenge.expires_at.timestamp().to_string()));
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<PasskeyChallenge> {
        let challenge_type_str = get_string(item, "challenge_type")?;
        let challenge_type = match challenge_type_str.as_str() {
            "Registration" => PasskeyChallengeType::Registration,
            "Authentication" => PasskeyChallengeType::Authentication,
            _ => return Err(TsaError::Database(format!("Invalid challenge type: {}", challenge_type_str))),
        };

        Ok(PasskeyChallenge {
            id: get_uuid(item, "id")?,
            user_id: get_uuid_opt(item, "user_id")?,
            challenge: get_bytes(item, "challenge")?,
            challenge_type,
            state: get_bytes(item, "state")?,
            expires_at: get_datetime(item, "expires_at")?,
            created_at: get_datetime(item, "created_at")?,
        })
    }
}

#[async_trait]
impl PasskeyChallengeRepository for DynamoDbPasskeyChallengeRepository {
    async fn create(&self, challenge: &PasskeyChallenge) -> Result<PasskeyChallenge> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(challenge)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(challenge.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<PasskeyChallenge>> {
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

    async fn find_by_challenge(&self, challenge: &[u8]) -> Result<Option<PasskeyChallenge>> {
        let challenge_b64 = STANDARD.encode(challenge);
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("challenge_b64-index")
            .key_condition_expression("challenge_b64 = :challenge")
            .expression_attribute_values(":challenge", AttributeValue::S(challenge_b64))
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
