use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use std::collections::HashMap;
use tsa_core::{OrganizationMember, OrganizationMemberRepository, OrganizationRole, Result, TsaError};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_ORGANIZATION_MEMBERS;

#[derive(Clone)]
pub struct DynamoDbOrganizationMemberRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbOrganizationMemberRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_ORGANIZATION_MEMBERS)
    }

    fn to_item(member: &OrganizationMember) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(member.id.to_string()));
        item.insert("organization_id".to_string(), AttributeValue::S(member.organization_id.to_string()));
        item.insert("user_id".to_string(), AttributeValue::S(member.user_id.to_string()));
        item.insert("org_user_key".to_string(), AttributeValue::S(format!("{}#{}", member.organization_id, member.user_id)));
        item.insert("role".to_string(), AttributeValue::S(member.role.to_string()));
        item.insert("created_at".to_string(), AttributeValue::S(member.created_at.to_rfc3339()));
        item.insert("updated_at".to_string(), AttributeValue::S(member.updated_at.to_rfc3339()));
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<OrganizationMember> {
        let role_str = get_string(item, "role")?;
        let role: OrganizationRole = role_str.parse()?;

        Ok(OrganizationMember {
            id: get_uuid(item, "id")?,
            organization_id: get_uuid(item, "organization_id")?,
            user_id: get_uuid(item, "user_id")?,
            role,
            created_at: get_datetime(item, "created_at")?,
            updated_at: get_datetime(item, "updated_at")?,
        })
    }
}

#[async_trait]
impl OrganizationMemberRepository for DynamoDbOrganizationMemberRepository {
    async fn create(&self, member: &OrganizationMember) -> Result<OrganizationMember> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(member)))
            .condition_expression("attribute_not_exists(id)")
            .send()
            .await
            .map_err(|e| {
                if e.to_string().contains("ConditionalCheckFailedException") {
                    TsaError::AlreadyOrganizationMember
                } else {
                    TsaError::Database(e.to_string())
                }
            })?;
        Ok(member.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<OrganizationMember>> {
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

    async fn find_by_org_and_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMember>> {
        let org_user_key = format!("{}#{}", organization_id, user_id);
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("org_user_key-index")
            .key_condition_expression("org_user_key = :key")
            .expression_attribute_values(":key", AttributeValue::S(org_user_key))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match result.items.and_then(|items| items.into_iter().next()) {
            Some(item) => Ok(Some(Self::from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn find_by_organization(&self, organization_id: Uuid) -> Result<Vec<OrganizationMember>> {
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

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<OrganizationMember>> {
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

    async fn update(&self, member: &OrganizationMember) -> Result<OrganizationMember> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(member)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(member.clone())
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

    async fn delete_by_organization(&self, organization_id: Uuid) -> Result<()> {
        let members = self.find_by_organization(organization_id).await?;
        for member in members {
            self.delete(member.id).await?;
        }
        Ok(())
    }
}
