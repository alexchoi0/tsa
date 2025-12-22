use async_trait::async_trait;
use tsa_auth_core::{ImpersonationSession, ImpersonationSessionRepository, Result};
use uuid::Uuid;

use super::super::{client::FirestoreClient, COLLECTION_IMPERSONATION_SESSIONS};

#[derive(Clone)]
pub struct FirestoreImpersonationSessionRepository {
    client: FirestoreClient,
}

impl FirestoreImpersonationSessionRepository {
    pub fn new(client: FirestoreClient) -> Self {
        Self { client }
    }
}

#[async_trait]
impl ImpersonationSessionRepository for FirestoreImpersonationSessionRepository {
    async fn create(&self, session: &ImpersonationSession) -> Result<ImpersonationSession> {
        self.client
            .create_document(
                COLLECTION_IMPERSONATION_SESSIONS,
                &session.id.to_string(),
                session,
            )
            .await?;
        Ok(session.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<ImpersonationSession>> {
        self.client
            .get_document(COLLECTION_IMPERSONATION_SESSIONS, &id.to_string())
            .await
    }

    async fn find_by_session_id(&self, session_id: Uuid) -> Result<Option<ImpersonationSession>> {
        self.client
            .find_by_field(
                COLLECTION_IMPERSONATION_SESSIONS,
                "session_id",
                &session_id.to_string(),
            )
            .await
    }

    async fn find_active_by_admin(&self, admin_id: Uuid) -> Result<Vec<ImpersonationSession>> {
        let sessions: Vec<ImpersonationSession> = self
            .client
            .find_all_by_field(
                COLLECTION_IMPERSONATION_SESSIONS,
                "admin_id",
                &admin_id.to_string(),
            )
            .await?;
        Ok(sessions
            .into_iter()
            .filter(|session| session.ended_at.is_none())
            .collect())
    }

    async fn find_by_target_user(&self, target_user_id: Uuid) -> Result<Vec<ImpersonationSession>> {
        self.client
            .find_all_by_field(
                COLLECTION_IMPERSONATION_SESSIONS,
                "target_user_id",
                &target_user_id.to_string(),
            )
            .await
    }

    async fn end_session(
        &self,
        id: Uuid,
        ended_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<ImpersonationSession> {
        if let Some(mut session) = self.find_by_id(id).await? {
            session.ended_at = Some(ended_at);
            self.client
                .update_document(
                    COLLECTION_IMPERSONATION_SESSIONS,
                    &session.id.to_string(),
                    &session,
                )
                .await?;
            Ok(session)
        } else {
            Err(tsa_auth_core::TsaError::Database(format!(
                "Impersonation session not found: {}",
                id
            )))
        }
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        self.client
            .delete_document(COLLECTION_IMPERSONATION_SESSIONS, &id.to_string())
            .await
    }
}
