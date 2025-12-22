use async_trait::async_trait;
use chrono::Utc;
use tsa_auth_core::{PasskeyChallenge, PasskeyChallengeRepository, Result};
use uuid::Uuid;

use super::super::{client::FirestoreClient, COLLECTION_PASSKEY_CHALLENGES};

#[derive(Clone)]
pub struct FirestorePasskeyChallengeRepository {
    client: FirestoreClient,
}

impl FirestorePasskeyChallengeRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl PasskeyChallengeRepository for FirestorePasskeyChallengeRepository {
    async fn create(&self, challenge: &PasskeyChallenge) -> Result<PasskeyChallenge> {
        self.client
            .create_document(
                COLLECTION_PASSKEY_CHALLENGES,
                &challenge.id.to_string(),
                challenge,
            )
            .await?;
        Ok(challenge.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<PasskeyChallenge>> {
        self.client
            .get_document(COLLECTION_PASSKEY_CHALLENGES, &id.to_string())
            .await
    }

    async fn find_by_challenge(&self, challenge: &[u8]) -> Result<Option<PasskeyChallenge>> {
        let challenges: Vec<PasskeyChallenge> = self
            .client
            .list_documents(COLLECTION_PASSKEY_CHALLENGES)
            .await?;
        for c in challenges {
            if c.challenge == challenge {
                return Ok(Some(c));
            }
        }
        Ok(None)
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_document(COLLECTION_PASSKEY_CHALLENGES, &id.to_string())
            .await
    }

    async fn delete_expired(&self) -> Result<u64> {
        let challenges: Vec<PasskeyChallenge> = self
            .client
            .list_documents(COLLECTION_PASSKEY_CHALLENGES)
            .await?;
        let now = Utc::now();
        let mut count = 0u64;
        for challenge in challenges {
            if challenge.expires_at < now {
                self.delete(challenge.id).await?;
                count += 1;
            }
        }
        Ok(count)
    }
}
