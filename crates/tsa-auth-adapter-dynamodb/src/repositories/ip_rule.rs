use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use chrono::Utc;
use std::collections::HashMap;
use tsa_auth_core::{IpRule, IpRuleRepository, IpRuleType, Result, TsaError};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_IP_RULES;

#[derive(Clone)]
pub struct DynamoDbIpRuleRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbIpRuleRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_IP_RULES)
    }

    fn to_item(rule: &IpRule) -> HashMap<String, AttributeValue> {
        let rule_type_str = match rule.rule_type {
            IpRuleType::Allow => "allow",
            IpRuleType::Block => "block",
        };

        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(rule.id.to_string()));
        item.insert(
            "ip_pattern".to_string(),
            AttributeValue::S(rule.ip_pattern.clone()),
        );
        item.insert(
            "rule_type".to_string(),
            AttributeValue::S(rule_type_str.to_string()),
        );
        if let Some(ref desc) = rule.description {
            item.insert("description".to_string(), AttributeValue::S(desc.clone()));
        }
        if let Some(ref expires) = rule.expires_at {
            item.insert(
                "expires_at".to_string(),
                AttributeValue::S(expires.to_rfc3339()),
            );
        }
        if let Some(ref created_by) = rule.created_by {
            item.insert(
                "created_by".to_string(),
                AttributeValue::S(created_by.to_string()),
            );
        }
        item.insert(
            "created_at".to_string(),
            AttributeValue::S(rule.created_at.to_rfc3339()),
        );
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<IpRule> {
        let rule_type_str = get_string(item, "rule_type")?;
        let rule_type = match rule_type_str.as_str() {
            "allow" => IpRuleType::Allow,
            "block" => IpRuleType::Block,
            _ => IpRuleType::Block,
        };

        Ok(IpRule {
            id: get_uuid(item, "id")?,
            ip_pattern: get_string(item, "ip_pattern")?,
            rule_type,
            description: get_string_opt(item, "description"),
            expires_at: get_datetime_opt(item, "expires_at")?,
            created_by: get_uuid_opt(item, "created_by")?,
            created_at: get_datetime(item, "created_at")?,
        })
    }
}

#[async_trait]
impl IpRuleRepository for DynamoDbIpRuleRepository {
    async fn create(&self, rule: &IpRule) -> Result<IpRule> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(rule)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(rule.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<IpRule>> {
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

    async fn find_all(&self) -> Result<Vec<IpRule>> {
        let result = self
            .client
            .scan()
            .table_name(self.table_name())
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

    async fn find_by_type(&self, rule_type: IpRuleType) -> Result<Vec<IpRule>> {
        let rule_type_str = match rule_type {
            IpRuleType::Allow => "allow",
            IpRuleType::Block => "block",
        };

        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("rule_type-index")
            .key_condition_expression("rule_type = :rule_type")
            .expression_attribute_values(":rule_type", AttributeValue::S(rule_type_str.to_string()))
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

    async fn find_active(&self) -> Result<Vec<IpRule>> {
        let now = Utc::now();
        let all_rules = self.find_all().await?;

        Ok(all_rules
            .into_iter()
            .filter(|rule| rule.expires_at.is_none() || rule.expires_at.unwrap() > now)
            .collect())
    }

    async fn update(&self, rule: &IpRule) -> Result<IpRule> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(rule)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(rule.clone())
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
        let all_rules = self.find_all().await?;

        let expired: Vec<_> = all_rules
            .into_iter()
            .filter(|rule| rule.expires_at.is_some_and(|exp| exp < now))
            .collect();

        let count = expired.len() as u64;

        for rule in expired {
            self.delete(rule.id).await?;
        }

        Ok(count)
    }
}
