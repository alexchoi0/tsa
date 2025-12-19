use async_trait::async_trait;
use chrono::Utc;
use tsa_core::{Result, VerificationToken, VerificationTokenRepository};
use uuid::Uuid;

use crate::client::BigtableClient;

const ENTITY_TYPE: &str = "verification_token";

#[derive(Clone)]
pub struct BigtableVerificationTokenRepository {
    client: BigtableClient,
}

impl BigtableVerificationTokenRepository {
    pub fn new(client: BigtableClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl VerificationTokenRepository for BigtableVerificationTokenRepository {
    async fn create(&self, token: &VerificationToken) -> Result<VerificationToken> {
        self.client
            .create_entity(ENTITY_TYPE, &token.id.to_string(), token)
            .await?;
        Ok(token.clone())
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<VerificationToken>> {
        self.client
            .find_by_field(ENTITY_TYPE, "token_hash", token_hash)
            .await
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_entity(ENTITY_TYPE, &id.to_string())
            .await
    }

    async fn delete_expired(&self) -> Result<u64> {
        let tokens: Vec<VerificationToken> = self.client.list_entities(ENTITY_TYPE).await?;
        let now = Utc::now();
        let mut count = 0u64;
        for token in tokens {
            if token.expires_at < now {
                self.delete(token.id).await?;
                count += 1;
            }
        }
        Ok(count)
    }
}
