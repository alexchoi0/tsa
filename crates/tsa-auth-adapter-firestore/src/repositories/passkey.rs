use async_trait::async_trait;
use tsa_auth_core::{Passkey, PasskeyRepository, Result};
use uuid::Uuid;

use crate::{client::FirestoreClient, COLLECTION_PASSKEYS};

#[derive(Clone)]
pub struct FirestorePasskeyRepository {
    client: FirestoreClient,
}

impl FirestorePasskeyRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PasskeyRepository for FirestorePasskeyRepository {
    async fn create(&self, passkey: &Passkey) -> Result<Passkey> {
        self.client
            .create_document(COLLECTION_PASSKEYS, &passkey.id.to_string(), passkey)
            .await?;
        Ok(passkey.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Passkey>> {
        self.client
            .get_document(COLLECTION_PASSKEYS, &id.to_string())
            .await
    }

    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Passkey>> {
        let passkeys: Vec<Passkey> = self.client.list_documents(COLLECTION_PASSKEYS).await?;
        for passkey in passkeys {
            if passkey.credential_id == credential_id {
                return Ok(Some(passkey));
            }
        }
        Ok(None)
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Passkey>> {
        self.client
            .find_all_by_field(COLLECTION_PASSKEYS, "user_id", &user_id.to_string())
            .await
    }

    async fn update(&self, passkey: &Passkey) -> Result<Passkey> {
        self.client
            .update_document(COLLECTION_PASSKEYS, &passkey.id.to_string(), passkey)
            .await?;
        Ok(passkey.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_document(COLLECTION_PASSKEYS, &id.to_string())
            .await
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        let passkeys = self.find_by_user(user_id).await?;
        for passkey in passkeys {
            self.delete(passkey.id).await?;
        }
        Ok(())
    }
}
