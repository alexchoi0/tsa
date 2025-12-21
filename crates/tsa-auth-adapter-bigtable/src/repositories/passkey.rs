use async_trait::async_trait;
use tsa_auth_core::{Passkey, PasskeyRepository, Result};
use uuid::Uuid;

use crate::client::BigtableClient;

const ENTITY_TYPE: &str = "passkey";

#[derive(Clone)]
pub struct BigtablePasskeyRepository {
    client: BigtableClient,
}

impl BigtablePasskeyRepository {
    pub fn new(client: BigtableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PasskeyRepository for BigtablePasskeyRepository {
    async fn create(&self, passkey: &Passkey) -> Result<Passkey> {
        self.client
            .create_entity(ENTITY_TYPE, &passkey.id.to_string(), passkey)
            .await?;
        Ok(passkey.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Passkey>> {
        self.client.get_entity(ENTITY_TYPE, &id.to_string()).await
    }

    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Passkey>> {
        let passkeys: Vec<Passkey> = self.client.list_entities(ENTITY_TYPE).await?;
        for passkey in passkeys {
            if passkey.credential_id == credential_id {
                return Ok(Some(passkey));
            }
        }
        Ok(None)
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Passkey>> {
        self.client
            .find_all_by_field(ENTITY_TYPE, "user_id", &user_id.to_string())
            .await
    }

    async fn update(&self, passkey: &Passkey) -> Result<Passkey> {
        self.client
            .update_entity(ENTITY_TYPE, &passkey.id.to_string(), passkey)
            .await?;
        Ok(passkey.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_entity(ENTITY_TYPE, &id.to_string())
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
