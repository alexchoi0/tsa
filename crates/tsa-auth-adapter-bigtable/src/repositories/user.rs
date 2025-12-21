use async_trait::async_trait;
use tsa_auth_core::{Result, TsaError, User, UserRepository};
use uuid::Uuid;

use crate::client::BigtableClient;

const ENTITY_TYPE: &str = "user";

#[derive(Clone)]
pub struct BigtableUserRepository {
    client: BigtableClient,
}

impl BigtableUserRepository {
    pub fn new(client: BigtableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl UserRepository for BigtableUserRepository {
    async fn create(&self, user: &User) -> Result<User> {
        if self.find_by_email(&user.email).await?.is_some() {
            return Err(TsaError::UserAlreadyExists);
        }
        self.client
            .create_entity(ENTITY_TYPE, &user.id.to_string(), user)
            .await?;
        Ok(user.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        self.client.get_entity(ENTITY_TYPE, &id.to_string()).await
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        self.client.find_by_field(ENTITY_TYPE, "email", email).await
    }

    async fn find_by_phone(&self, phone: &str) -> Result<Option<User>> {
        self.client.find_by_field(ENTITY_TYPE, "phone", phone).await
    }

    async fn update(&self, user: &User) -> Result<User> {
        self.client
            .update_entity(ENTITY_TYPE, &user.id.to_string(), user)
            .await?;
        Ok(user.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_entity(ENTITY_TYPE, &id.to_string())
            .await
    }
}
