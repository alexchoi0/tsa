use async_trait::async_trait;
use chrono::Utc;
use tsa_auth_core::{IpRule, IpRuleRepository, IpRuleType, Result};
use uuid::Uuid;

use crate::{client::FirestoreClient, COLLECTION_IP_RULES};

#[derive(Clone)]
pub struct FirestoreIpRuleRepository {
    client: FirestoreClient,
}

impl FirestoreIpRuleRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl IpRuleRepository for FirestoreIpRuleRepository {
    async fn create(&self, rule: &IpRule) -> Result<IpRule> {
        self.client
            .create_document(COLLECTION_IP_RULES, &rule.id.to_string(), rule)
            .await?;
        Ok(rule.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<IpRule>> {
        self.client
            .get_document(COLLECTION_IP_RULES, &id.to_string())
            .await
    }

    async fn find_all(&self) -> Result<Vec<IpRule>> {
        self.client.list_documents(COLLECTION_IP_RULES).await
    }

    async fn find_by_type(&self, rule_type: IpRuleType) -> Result<Vec<IpRule>> {
        let rule_type_str = serde_json::to_string(&rule_type).unwrap_or_default();
        let rule_type_str = rule_type_str.trim_matches('"');
        self.client
            .find_all_by_field(COLLECTION_IP_RULES, "rule_type", rule_type_str)
            .await
    }

    async fn find_active(&self) -> Result<Vec<IpRule>> {
        let rules: Vec<IpRule> = self.client.list_documents(COLLECTION_IP_RULES).await?;
        let now = Utc::now();
        Ok(rules
            .into_iter()
            .filter(|rule| rule.expires_at.is_none_or(|expires| expires > now))
            .collect())
    }

    async fn update(&self, rule: &IpRule) -> Result<IpRule> {
        self.client
            .update_document(COLLECTION_IP_RULES, &rule.id.to_string(), rule)
            .await?;
        Ok(rule.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_document(COLLECTION_IP_RULES, &id.to_string())
            .await
    }

    async fn delete_expired(&self) -> Result<u64> {
        let rules: Vec<IpRule> = self.client.list_documents(COLLECTION_IP_RULES).await?;
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
