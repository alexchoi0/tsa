use async_trait::async_trait;
use chrono::Utc;
use tsa_core::{Result, Session, SessionRepository};
use uuid::Uuid;

use crate::{client::FirestoreClient, COLLECTION_SESSIONS};

#[derive(Clone)]
pub struct FirestoreSessionRepository {
    client: FirestoreClient,
}

impl FirestoreSessionRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl SessionRepository for FirestoreSessionRepository {
    async fn create(&self, session: &Session) -> Result<Session> {
        self.client
            .create_document(COLLECTION_SESSIONS, &session.id.to_string(), session)
            .await?;
        Ok(session.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Session>> {
        self.client
            .get_document(COLLECTION_SESSIONS, &id.to_string())
            .await
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>> {
        self.client
            .find_by_field(COLLECTION_SESSIONS, "token_hash", token_hash)
            .await
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Session>> {
        self.client
            .find_all_by_field(COLLECTION_SESSIONS, "user_id", &user_id.to_string())
            .await
    }

    async fn update(&self, session: &Session) -> Result<Session> {
        self.client
            .update_document(COLLECTION_SESSIONS, &session.id.to_string(), session)
            .await?;
        Ok(session.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_document(COLLECTION_SESSIONS, &id.to_string())
            .await
    }

    async fn delete_by_user_id(&self, user_id: Uuid) -> Result<()> {
        let sessions = self.find_by_user_id(user_id).await?;
        for session in sessions {
            self.delete(session.id).await?;
        }
        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64> {
        let sessions: Vec<Session> = self.client.list_documents(COLLECTION_SESSIONS).await?;
        let now = Utc::now();
        let mut count = 0u64;
        for session in sessions {
            if session.expires_at < now {
                self.delete(session.id).await?;
                count += 1;
            }
        }
        Ok(count)
    }
}
