use async_trait::async_trait;
use chrono::Utc;
use futures::TryStreamExt;
use mongodb::{bson::doc, Collection, Database};
use tsa_auth_core::{IpRule, IpRuleRepository, IpRuleType, Result, TsaError};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbIpRuleRepository {
    collection: Collection<IpRule>,
}

impl MongoDbIpRuleRepository {
    pub fn new(collection: Collection<IpRule>) -> Self {
        Self { collection }
    }

    pub fn from_database(db: &Database) -> Self {
        Self::new(db.collection::<IpRule>("ip_rules"))
    }
}

#[async_trait]
impl IpRuleRepository for MongoDbIpRuleRepository {
    async fn create(&self, rule: &IpRule) -> Result<IpRule> {
        self.collection
            .insert_one(rule)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(rule.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<IpRule>> {
        self.collection
            .find_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_all(&self) -> Result<Vec<IpRule>> {
        let cursor = self
            .collection
            .find(doc! {})
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        cursor
            .try_collect()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_type(&self, rule_type: IpRuleType) -> Result<Vec<IpRule>> {
        let rule_type_str = match rule_type {
            IpRuleType::Allow => "allow",
            IpRuleType::Block => "block",
        };

        let cursor = self
            .collection
            .find(doc! { "rule_type": rule_type_str })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        cursor
            .try_collect()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_active(&self) -> Result<Vec<IpRule>> {
        let now = Utc::now();
        let cursor = self
            .collection
            .find(doc! {
                "$or": [
                    { "expires_at": null },
                    { "expires_at": { "$gt": now } }
                ]
            })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        cursor
            .try_collect()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn update(&self, rule: &IpRule) -> Result<IpRule> {
        self.collection
            .replace_one(doc! { "id": rule.id }, rule)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(rule.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.collection
            .delete_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64> {
        let now = Utc::now();
        let result = self
            .collection
            .delete_many(doc! { "expires_at": { "$lt": now } })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(result.deleted_count)
    }
}
