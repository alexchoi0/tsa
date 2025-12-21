use async_trait::async_trait;
use tsa_auth_core::{Result, TwoFactor, TwoFactorRepository};
use uuid::Uuid;

use crate::{client::FirestoreClient, COLLECTION_TWO_FACTORS};

#[derive(Clone)]
pub struct FirestoreTwoFactorRepository {
    client: FirestoreClient,
}

impl FirestoreTwoFactorRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl TwoFactorRepository for FirestoreTwoFactorRepository {
    async fn create(&self, two_factor: &TwoFactor) -> Result<TwoFactor> {
        self.client
            .create_document(COLLECTION_TWO_FACTORS, &two_factor.id.to_string(), two_factor)
            .await?;
        Ok(two_factor.clone())
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<TwoFactor>> {
        self.client
            .find_by_field(COLLECTION_TWO_FACTORS, "user_id", &user_id.to_string())
            .await
    }

    async fn update(&self, two_factor: &TwoFactor) -> Result<TwoFactor> {
        self.client
            .update_document(
                COLLECTION_TWO_FACTORS,
                &two_factor.id.to_string(),
                two_factor,
            )
            .await?;
        Ok(two_factor.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_document(COLLECTION_TWO_FACTORS, &id.to_string())
            .await
    }

    async fn delete_by_user_id(&self, user_id: Uuid) -> Result<()> {
        if let Some(two_factor) = self.find_by_user_id(user_id).await? {
            self.delete(two_factor.id).await?;
        }
        Ok(())
    }
}
