use async_trait::async_trait;
use mongodb::{bson::doc, Collection};
use tsa_auth_core::{Result, TsaError, TwoFactor, TwoFactorRepository};
use uuid::Uuid;

#[derive(Clone)]
pub struct MongoDbTwoFactorRepository {
    collection: Collection<TwoFactor>,
}

impl MongoDbTwoFactorRepository {
    pub fn new(collection: Collection<TwoFactor>) -> Self {
        Self { collection }
    }
}

#[async_trait]
impl TwoFactorRepository for MongoDbTwoFactorRepository {
    async fn create(&self, two_factor: &TwoFactor) -> Result<TwoFactor> {
        self.collection.insert_one(two_factor).await.map_err(|e| {
            if e.to_string().contains("duplicate key") {
                TsaError::TwoFactorAlreadyEnabled
            } else {
                TsaError::Database(e.to_string())
            }
        })?;
        Ok(two_factor.clone())
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<TwoFactor>> {
        self.collection
            .find_one(doc! { "user_id": user_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))
    }

    async fn update(&self, two_factor: &TwoFactor) -> Result<TwoFactor> {
        self.collection
            .replace_one(doc! { "id": two_factor.id }, two_factor)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(two_factor.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.collection
            .delete_one(doc! { "id": id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }

    async fn delete_by_user_id(&self, user_id: Uuid) -> Result<()> {
        self.collection
            .delete_many(doc! { "user_id": user_id })
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(())
    }
}
