use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use std::collections::HashMap;
use tsa_core::{Organization, OrganizationRepository, Result, TsaError};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_ORGANIZATIONS;

#[derive(Clone)]
pub struct DynamoDbOrganizationRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbOrganizationRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_ORGANIZATIONS)
    }

    fn to_item(org: &Organization) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(org.id.to_string()));
        item.insert("name".to_string(), AttributeValue::S(org.name.clone()));
        item.insert("slug".to_string(), AttributeValue::S(org.slug.clone()));
        if let Some(ref logo) = org.logo {
            item.insert("logo".to_string(), AttributeValue::S(logo.clone()));
        }
        if let Some(ref metadata) = org.metadata {
            item.insert("metadata".to_string(), AttributeValue::S(metadata.to_string()));
        }
        item.insert("created_at".to_string(), AttributeValue::S(org.created_at.to_rfc3339()));
        item.insert("updated_at".to_string(), AttributeValue::S(org.updated_at.to_rfc3339()));
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<Organization> {
        let metadata = get_string_opt(item, "metadata")
            .and_then(|s| serde_json::from_str(&s).ok());

        Ok(Organization {
            id: get_uuid(item, "id")?,
            name: get_string(item, "name")?,
            slug: get_string(item, "slug")?,
            logo: get_string_opt(item, "logo"),
            metadata,
            created_at: get_datetime(item, "created_at")?,
            updated_at: get_datetime(item, "updated_at")?,
        })
    }
}

#[async_trait]
impl OrganizationRepository for DynamoDbOrganizationRepository {
    async fn create(&self, organization: &Organization) -> Result<Organization> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(organization)))
            .condition_expression("attribute_not_exists(id)")
            .send()
            .await
            .map_err(|e| {
                if e.to_string().contains("ConditionalCheckFailedException") {
                    TsaError::OrganizationAlreadyExists
                } else {
                    TsaError::Database(e.to_string())
                }
            })?;
        Ok(organization.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>> {
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

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("slug-index")
            .key_condition_expression("slug = :slug")
            .expression_attribute_values(":slug", AttributeValue::S(slug.to_string()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match result.items.and_then(|items| items.into_iter().next()) {
            Some(item) => Ok(Some(Self::from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn update(&self, organization: &Organization) -> Result<Organization> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(organization)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(organization.clone())
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
