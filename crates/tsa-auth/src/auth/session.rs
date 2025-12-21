use chrono::Utc;
use tsa_auth_core::{Adapter, Result, Session, SessionRepository, TsaError, User, UserRepository};
use tsa_auth_token::OpaqueToken;
use uuid::Uuid;

use crate::webhook::WebhookSender;
use crate::AuthCallbacks;

use super::Auth;

impl<A: Adapter, C: AuthCallbacks, W: WebhookSender> Auth<A, C, W> {
    pub async fn validate_session(&self, session_token: &str) -> Result<(User, Session)> {
        let token_hash = OpaqueToken::hash(session_token);
        let mut session = self
            .adapter
            .sessions()
            .find_by_token_hash(&token_hash)
            .await?
            .ok_or(TsaError::SessionNotFound)?;

        let now = Utc::now();
        if session.expires_at < now {
            self.adapter.sessions().delete(session.id).await?;
            return Err(TsaError::SessionExpired);
        }

        if self.config.enable_session_refresh {
            let time_remaining = session.expires_at - now;
            if time_remaining < self.config.session_refresh_threshold {
                session.expires_at = now + self.config.session_expiry;
                session = self.adapter.sessions().update(&session).await?;
            }
        }

        let user = self
            .adapter
            .users()
            .find_by_id(session.user_id)
            .await?
            .ok_or(TsaError::UserNotFound)?;

        Ok((user, session))
    }

    pub async fn refresh_session(&self, session_token: &str) -> Result<Session> {
        let token_hash = OpaqueToken::hash(session_token);
        let mut session = self
            .adapter
            .sessions()
            .find_by_token_hash(&token_hash)
            .await?
            .ok_or(TsaError::SessionNotFound)?;

        if session.expires_at < Utc::now() {
            self.adapter.sessions().delete(session.id).await?;
            return Err(TsaError::SessionExpired);
        }

        session.expires_at = Utc::now() + self.config.session_expiry;
        let session = self.adapter.sessions().update(&session).await?;

        Ok(session)
    }

    pub async fn get_user_sessions(&self, user_id: Uuid) -> Result<Vec<Session>> {
        self.adapter.sessions().find_by_user_id(user_id).await
    }

    pub async fn revoke_session(&self, session_id: Uuid) -> Result<()> {
        self.adapter.sessions().delete(session_id).await
    }

    pub async fn revoke_all_sessions(&self, user_id: Uuid) -> Result<()> {
        self.adapter.sessions().delete_by_user_id(user_id).await
    }

    pub async fn revoke_other_sessions(
        &self,
        user_id: Uuid,
        current_session_id: Uuid,
    ) -> Result<()> {
        let sessions = self.adapter.sessions().find_by_user_id(user_id).await?;
        for session in sessions {
            if session.id != current_session_id {
                self.adapter.sessions().delete(session.id).await?;
            }
        }
        Ok(())
    }
}
