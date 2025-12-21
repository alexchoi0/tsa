use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use chrono::Utc;
use std::collections::HashMap;
use tsa_auth_core::{
    InvitationStatus, OrganizationInvitation, OrganizationInvitationRepository, OrganizationRole,
    Result, TsaError,
};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_ORGANIZATION_INVITATIONS;

#[derive(Clone)]
pub struct DynamoDbOrganizationInvitationRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbOrganizationInvitationRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_ORGANIZATION_INVITATIONS)
    }

    fn to_item(invitation: &OrganizationInvitation) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert(
            "id".to_string(),
            AttributeValue::S(invitation.id.to_string()),
        );
        item.insert(
            "organization_id".to_string(),
            AttributeValue::S(invitation.organization_id.to_string()),
        );
        item.insert(
            "email".to_string(),
            AttributeValue::S(invitation.email.clone()),
        );
        item.insert(
            "role".to_string(),
            AttributeValue::S(invitation.role.to_string()),
        );
        item.insert(
            "token_hash".to_string(),
            AttributeValue::S(invitation.token_hash.clone()),
        );
        item.insert(
            "invited_by".to_string(),
            AttributeValue::S(invitation.invited_by.to_string()),
        );
        item.insert(
            "status".to_string(),
            AttributeValue::S(invitation.status.to_string()),
        );
        item.insert(
            "expires_at".to_string(),
            AttributeValue::S(invitation.expires_at.to_rfc3339()),
        );
        item.insert(
            "created_at".to_string(),
            AttributeValue::S(invitation.created_at.to_rfc3339()),
        );
        item.insert(
            "ttl".to_string(),
            AttributeValue::N(invitation.expires_at.timestamp().to_string()),
        );
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<OrganizationInvitation> {
        let role_str = get_string(item, "role")?;
        let role: OrganizationRole = role_str.parse()?;

        let status_str = get_string(item, "status")?;
        let status: InvitationStatus = status_str.parse()?;

        Ok(OrganizationInvitation {
            id: get_uuid(item, "id")?,
            organization_id: get_uuid(item, "organization_id")?,
            email: get_string(item, "email")?,
            role,
            token_hash: get_string(item, "token_hash")?,
            invited_by: get_uuid(item, "invited_by")?,
            status,
            expires_at: get_datetime(item, "expires_at")?,
            created_at: get_datetime(item, "created_at")?,
        })
    }
}

#[async_trait]
impl OrganizationInvitationRepository for DynamoDbOrganizationInvitationRepository {
    async fn create(&self, invitation: &OrganizationInvitation) -> Result<OrganizationInvitation> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(invitation)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(invitation.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<OrganizationInvitation>> {
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

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<OrganizationInvitation>> {
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

    async fn find_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationInvitation>> {
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

    async fn find_by_email(&self, email: &str) -> Result<Vec<OrganizationInvitation>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("email-index")
            .key_condition_expression("email = :email")
            .expression_attribute_values(":email", AttributeValue::S(email.to_string()))
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

    async fn find_pending_by_org_and_email(
        &self,
        organization_id: Uuid,
        email: &str,
    ) -> Result<Option<OrganizationInvitation>> {
        let invitations = self.find_by_organization(organization_id).await?;
        Ok(invitations
            .into_iter()
            .find(|inv| inv.email == email && inv.status == InvitationStatus::Pending))
    }

    async fn update(&self, invitation: &OrganizationInvitation) -> Result<OrganizationInvitation> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(invitation)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(invitation.clone())
    }

    async fn update_status(&self, id: Uuid, status: InvitationStatus) -> Result<()> {
        self.client
            .update_item()
            .table_name(self.table_name())
            .key("id", AttributeValue::S(id.to_string()))
            .update_expression("SET #status = :status")
            .expression_attribute_names("#status", "status")
            .expression_attribute_values(":status", AttributeValue::S(status.to_string()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
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
