use async_trait::async_trait;
use tsa_auth_core::{Result, TsaError, User, UserRepository};
use uuid::Uuid;

use super::super::{client::FirestoreClient, COLLECTION_USERS};

#[derive(Clone)]
pub struct FirestoreUserRepository {
    client: FirestoreClient,
}

impl FirestoreUserRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl UserRepository for FirestoreUserRepository {
    async fn create(&self, user: &User) -> Result<User> {
        if self.find_by_email(&user.email).await?.is_some() {
            return Err(TsaError::UserAlreadyExists);
        }
        self.client
            .create_document(COLLECTION_USERS, &user.id.to_string(), user)
            .await?;
        Ok(user.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        self.client
            .get_document(COLLECTION_USERS, &id.to_string())
            .await
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        self.client
            .find_by_field(COLLECTION_USERS, "email", email)
            .await
    }

    async fn find_by_phone(&self, phone: &str) -> Result<Option<User>> {
        self.client
            .find_by_field(COLLECTION_USERS, "phone", phone)
            .await
    }

    async fn update(&self, user: &User) -> Result<User> {
        self.client
            .update_document(COLLECTION_USERS, &user.id.to_string(), user)
            .await?;
        Ok(user.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_document(COLLECTION_USERS, &id.to_string())
            .await
    }
}
