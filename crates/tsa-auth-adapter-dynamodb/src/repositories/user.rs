use async_trait::async_trait;
use aws_sdk_dynamodb::{types::AttributeValue, Client};
use std::collections::HashMap;
use tsa_auth_core::{Result, TsaError, User, UserRepository};
use uuid::Uuid;

use super::utils::*;
use crate::TABLE_USERS;

#[derive(Clone)]
pub struct DynamoDbUserRepository {
    client: Client,
    table_prefix: String,
}

impl DynamoDbUserRepository {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            client,
            table_prefix: table_prefix.to_string(),
        }
    }

    fn table_name(&self) -> String {
        format!("{}{}", self.table_prefix, TABLE_USERS)
    }

    fn to_item(user: &User) -> HashMap<String, AttributeValue> {
        let mut item = HashMap::new();
        item.insert("id".to_string(), AttributeValue::S(user.id.to_string()));
        item.insert("email".to_string(), AttributeValue::S(user.email.clone()));
        item.insert("email_verified".to_string(), AttributeValue::Bool(user.email_verified));
        if let Some(ref phone) = user.phone {
            item.insert("phone".to_string(), AttributeValue::S(phone.clone()));
        }
        item.insert("phone_verified".to_string(), AttributeValue::Bool(user.phone_verified));
        if let Some(ref name) = user.name {
            item.insert("name".to_string(), AttributeValue::S(name.clone()));
        }
        if let Some(ref image) = user.image {
            item.insert("image".to_string(), AttributeValue::S(image.clone()));
        }
        item.insert("created_at".to_string(), AttributeValue::S(user.created_at.to_rfc3339()));
        item.insert("updated_at".to_string(), AttributeValue::S(user.updated_at.to_rfc3339()));
        item
    }

    fn from_item(item: &HashMap<String, AttributeValue>) -> Result<User> {
        Ok(User {
            id: get_uuid(item, "id")?,
            email: get_string(item, "email")?,
            email_verified: get_bool(item, "email_verified")?,
            phone: get_string_opt(item, "phone"),
            phone_verified: get_bool(item, "phone_verified")?,
            name: get_string_opt(item, "name"),
            image: get_string_opt(item, "image"),
            created_at: get_datetime(item, "created_at")?,
            updated_at: get_datetime(item, "updated_at")?,
        })
    }
}

#[async_trait]
impl UserRepository for DynamoDbUserRepository {
    async fn create(&self, user: &User) -> Result<User> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(user)))
            .condition_expression("attribute_not_exists(id)")
            .send()
            .await
            .map_err(|e| {
                if e.to_string().contains("ConditionalCheckFailedException") {
                    TsaError::UserAlreadyExists
                } else {
                    TsaError::Database(e.to_string())
                }
            })?;
        Ok(user.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
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

    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
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

        match result.items.and_then(|items| items.into_iter().next()) {
            Some(item) => Ok(Some(Self::from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn find_by_phone(&self, phone: &str) -> Result<Option<User>> {
        let result = self
            .client
            .query()
            .table_name(self.table_name())
            .index_name("phone-index")
            .key_condition_expression("phone = :phone")
            .expression_attribute_values(":phone", AttributeValue::S(phone.to_string()))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match result.items.and_then(|items| items.into_iter().next()) {
            Some(item) => Ok(Some(Self::from_item(&item)?)),
            None => Ok(None),
        }
    }

    async fn update(&self, user: &User) -> Result<User> {
        self.client
            .put_item()
            .table_name(self.table_name())
            .set_item(Some(Self::to_item(user)))
            .send()
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(user.clone())
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
