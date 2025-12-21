use async_trait::async_trait;
use mongodb::{bson::doc, Collection};
use tsa_auth_core::{Result, TsaError, User, UserRepository};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbUserRepository {
    collection: Collection<User>,
}

impl MongoDbUserRepository {
    pub fn new(collection: Collection<User>) -> Self {
        Self { collection }
    }
}

#[async_trait]
impl UserRepository for MongoDbUserRepository {
    async fn create(&self, user: &User) -> Result<User> {
        self.collection
            .insert_one(user)
            .await
            .map_err(|e| {
                if e.to_string().contains("duplicate key") {
                    TsaError::UserAlreadyExists
                } else {
                    TsaError::Database(e.to_string())
                }
            })?;
        Ok(user.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        self.collection
            .find_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        self.collection
            .find_one(doc! { "email": email })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn find_by_phone(&self, phone: &str) -> Result<Option<User>> {
        self.collection
            .find_one(doc! { "phone": phone })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn update(&self, user: &User) -> Result<User> {
        self.collection
            .replace_one(doc! { "id": user.id }, user)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(user.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.collection
            .delete_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }
}
