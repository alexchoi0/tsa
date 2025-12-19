use async_trait::async_trait;
use chrono::Utc;
use tsa_core::{Result, VerificationToken, VerificationTokenRepository};
use uuid::Uuid;

use crate::{client::FirestoreClient, COLLECTION_VERIFICATION_TOKENS};

#[derive(Clone)]
pub struct FirestoreVerificationTokenRepository {
    client: FirestoreClient,
}

impl FirestoreVerificationTokenRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl VerificationTokenRepository for FirestoreVerificationTokenRepository {
    async fn create(&self, token: &VerificationToken) -> Result<VerificationToken> {
        self.client
            .create_document(
                COLLECTION_VERIFICATION_TOKENS,
                &token.id.to_string(),
                token,
            )
            .await?;
        Ok(token.clone())
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<VerificationToken>> {
        self.client
            .find_by_field(COLLECTION_VERIFICATION_TOKENS, "token_hash", token_hash)
            .await
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_document(COLLECTION_VERIFICATION_TOKENS, &id.to_string())
            .await
    }

    async fn delete_expired(&self) -> Result<u64> {
        let tokens: Vec<VerificationToken> = self
            .client
            .list_documents(COLLECTION_VERIFICATION_TOKENS)
            .await?;
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
