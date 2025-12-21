use chrono::Utc;
use tsa_auth_core::{
    Adapter, Result, Session, TokenType, TsaError, User, UserRepository, VerificationToken,
    VerificationTokenRepository, WebhookData, WebhookEvent, UserWebhookData, AuthWebhookData,
    SessionWebhookData,
};
use tsa_auth_token::OpaqueToken;
use uuid::Uuid;

use crate::webhook::WebhookSender;
use crate::AuthCallbacks;

use super::Auth;

impl<A: Adapter, C: AuthCallbacks, W: WebhookSender> Auth<A, C, W> {
    pub async fn send_magic_link(&self, email: &str) -> Result<()> {
        let user = match self.adapter.users().find_by_email(email).await? {
            Some(user) => user,
            None => return Ok(()),
        };

        let (token, token_hash) = OpaqueToken::generate_with_hash(32)?;
        let now = Utc::now();

        let verification = VerificationToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash,
            token_type: TokenType::MagicLink,
            expires_at: now + self.config.magic_link_expiry,
            created_at: now,
        };

        self.adapter
            .verification_tokens()
            .create(&verification)
            .await?;

        self.callbacks.send_magic_link_email(&user, &token).await?;

        self.send_webhook(
            WebhookEvent::MagicLinkSent,
            WebhookData::User(UserWebhookData {
                user_id: user.id,
                email: user.email,
                name: user.name,
            }),
        )
        .await;

        Ok(())
    }

    pub async fn verify_magic_link(
        &self,
        token: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(User, Session, String)> {
        let token_hash = OpaqueToken::hash(token);
        let verification = self
            .adapter
            .verification_tokens()
            .find_by_token_hash(&token_hash)
            .await?
            .ok_or(TsaError::InvalidToken)?;

        if verification.token_type != TokenType::MagicLink {
            return Err(TsaError::InvalidToken);
        }

        if verification.expires_at < Utc::now() {
            self.adapter
                .verification_tokens()
                .delete(verification.id)
                .await?;
            return Err(TsaError::TokenExpired);
        }

        let mut user = self
            .adapter
            .users()
            .find_by_id(verification.user_id)
            .await?
            .ok_or(TsaError::UserNotFound)?;

        if !user.email_verified {
            user.email_verified = true;
            user.updated_at = Utc::now();
            user = self.adapter.users().update(&user).await?;
        }

        self.adapter
            .verification_tokens()
            .delete(verification.id)
            .await?;

        let (session, session_token) = self
            .create_session_internal(&user, ip_address, user_agent)
            .await?;

        self.send_webhook(
            WebhookEvent::MagicLinkVerified,
            WebhookData::Auth(AuthWebhookData {
                user_id: user.id,
                email: user.email.clone(),
                ip_address: session.ip_address.clone(),
                user_agent: session.user_agent.clone(),
                failure_reason: None,
            }),
        )
        .await;

        self.send_webhook(
            WebhookEvent::SessionCreated,
            WebhookData::Session(SessionWebhookData {
                session_id: session.id,
                user_id: user.id,
                ip_address: session.ip_address.clone(),
                user_agent: session.user_agent.clone(),
            }),
        )
        .await;

        Ok((user, session, session_token))
    }
}
