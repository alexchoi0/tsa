use async_trait::async_trait;
use chrono::Utc;
use tsa_auth_core::{IpRule, IpRuleRepository, IpRuleType, Result};
use uuid::Uuid;

use crate::client::BigtableClient;

const ENTITY_TYPE: &str = "ip_rule";

#[derive(Clone)]
pub struct BigtableIpRuleRepository {
    client: BigtableClient,
}

impl BigtableIpRuleRepository {
    pub fn new(client: BigtableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl IpRuleRepository for BigtableIpRuleRepository {
    async fn create(&self, rule: &IpRule) -> Result<IpRule> {
        self.client
            .create_entity(ENTITY_TYPE, &rule.id.to_string(), rule)
            .await?;
        Ok(rule.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<IpRule>> {
        self.client.get_entity(ENTITY_TYPE, &id.to_string()).await
    }

    async fn find_all(&self) -> Result<Vec<IpRule>> {
        self.client.list_entities(ENTITY_TYPE).await
    }

    async fn find_by_type(&self, rule_type: IpRuleType) -> Result<Vec<IpRule>> {
        let all_rules: Vec<IpRule> = self.client.list_entities(ENTITY_TYPE).await?;
        Ok(all_rules
            .into_iter()
            .filter(|rule| rule.rule_type == rule_type)
            .collect())
    }

    async fn find_active(&self) -> Result<Vec<IpRule>> {
        let all_rules: Vec<IpRule> = self.client.list_entities(ENTITY_TYPE).await?;
        let now = Utc::now();
        Ok(all_rules
            .into_iter()
            .filter(|rule| {
                rule.expires_at.map_or(true, |exp| exp > now)
            })
            .collect())
    }

    async fn update(&self, rule: &IpRule) -> Result<IpRule> {
        self.client
            .update_entity(ENTITY_TYPE, &rule.id.to_string(), rule)
            .await?;
        Ok(rule.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_entity(ENTITY_TYPE, &id.to_string())
            .await
    }

    async fn delete_expired(&self) -> Result<u64> {
        let rules: Vec<IpRule> = self.client.list_entities(ENTITY_TYPE).await?;
        let now = Utc::now();
        let mut count = 0u64;
        for rule in rules {
            if let Some(expires_at) = rule.expires_at {
                if expires_at < now {
                    self.delete(rule.id).await?;
                    count += 1;
                }
            }
        }
        Ok(count)
    }
}
