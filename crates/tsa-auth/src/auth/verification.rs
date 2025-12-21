use chrono::Utc;
use tsa_auth_core::{
    Adapter, Result, TokenType, TsaError, User, UserRepository, VerificationTokenRepository,
    WebhookData, WebhookEvent, UserWebhookData,
};
use tsa_auth_token::OpaqueToken;

use crate::webhook::WebhookSender;
use crate::AuthCallbacks;

use super::Auth;

impl<A: Adapter, C: AuthCallbacks, W: WebhookSender> Auth<A, C, W> {
    pub async fn send_verification_email(&self, email: &str) -> Result<()> {
        let user = self
            .adapter
            .users()
            .find_by_email(email)
            .await?
            .ok_or(TsaError::UserNotFound)?;

        if user.email_verified {
            return Ok(());
        }

        self.send_verification_email_internal(&user).await
    }

    pub async fn verify_email(&self, token: &str) -> Result<User> {
        let token_hash = OpaqueToken::hash(token);
        let verification = self
            .adapter
            .verification_tokens()
            .find_by_token_hash(&token_hash)
            .await?
            .ok_or(TsaError::InvalidToken)?;

        if verification.token_type != TokenType::EmailVerification {
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

        user.email_verified = true;
        user.updated_at = Utc::now();
        let user = self.adapter.users().update(&user).await?;

        self.adapter
            .verification_tokens()
            .delete(verification.id)
            .await?;

        self.send_webhook(
            WebhookEvent::EmailVerified,
            WebhookData::User(UserWebhookData {
                user_id: user.id,
                email: user.email.clone(),
                name: user.name.clone(),
            }),
        )
        .await;

        Ok(user)
    }
}
