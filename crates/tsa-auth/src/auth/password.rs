use chrono::Utc;
use tsa_auth_core::{
    AccountRepository, Adapter, Result, SessionRepository, TokenType, TsaError, UserRepository,
    UserWebhookData, VerificationToken, VerificationTokenRepository, WebhookData, WebhookEvent,
};
use tsa_auth_token::OpaqueToken;
use uuid::Uuid;

use crate::webhook::WebhookSender;
use crate::{AuthCallbacks, Password};

use super::Auth;

impl<A: Adapter, C: AuthCallbacks, W: WebhookSender> Auth<A, C, W> {
    pub async fn request_password_reset(&self, email: &str) -> Result<()> {
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
            token_type: TokenType::PasswordReset,
            expires_at: now + self.config.password_reset_token_expiry,
            created_at: now,
        };

        self.adapter
            .verification_tokens()
            .create(&verification)
            .await?;

        self.callbacks
            .send_password_reset_email(&user, &token)
            .await?;

        self.send_webhook(
            WebhookEvent::PasswordResetRequested,
            WebhookData::User(UserWebhookData {
                user_id: user.id,
                email: user.email.clone(),
                name: user.name.clone(),
            }),
        )
        .await;

        Ok(())
    }

    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<()> {
        let token_hash = OpaqueToken::hash(token);
        let verification = self
            .adapter
            .verification_tokens()
            .find_by_token_hash(&token_hash)
            .await?
            .ok_or(TsaError::InvalidToken)?;

        if verification.token_type != TokenType::PasswordReset {
            return Err(TsaError::InvalidToken);
        }

        if verification.expires_at < Utc::now() {
            self.adapter
                .verification_tokens()
                .delete(verification.id)
                .await?;
            return Err(TsaError::TokenExpired);
        }

        let password_hash = Password::hash(new_password)?;
        self.update_password_hash(verification.user_id, &password_hash)
            .await?;

        self.adapter
            .verification_tokens()
            .delete(verification.id)
            .await?;

        self.adapter
            .sessions()
            .delete_by_user_id(verification.user_id)
            .await?;

        if let Some(user) = self
            .adapter
            .users()
            .find_by_id(verification.user_id)
            .await?
        {
            self.send_webhook(
                WebhookEvent::PasswordChanged,
                WebhookData::User(UserWebhookData {
                    user_id: user.id,
                    email: user.email,
                    name: user.name,
                }),
            )
            .await;
        }

        Ok(())
    }

    pub async fn change_password(
        &self,
        user_id: Uuid,
        current_password: &str,
        new_password: &str,
        revoke_other_sessions: bool,
        current_session_id: Option<Uuid>,
    ) -> Result<()> {
        let accounts = self.adapter.accounts().find_by_user_id(user_id).await?;
        let _credential_account = accounts
            .iter()
            .find(|a| a.provider == "credential")
            .ok_or(TsaError::InvalidCredentials)?;

        let password_hash = self
            .get_password_hash(user_id)
            .await?
            .ok_or(TsaError::InvalidCredentials)?;

        if !Password::verify(current_password, &password_hash)? {
            return Err(TsaError::InvalidCredentials);
        }

        let new_hash = Password::hash(new_password)?;
        self.update_password_hash(user_id, &new_hash).await?;

        if revoke_other_sessions {
            if let Some(session_id) = current_session_id {
                self.revoke_other_sessions(user_id, session_id).await?;
            } else {
                self.revoke_all_sessions(user_id).await?;
            }
        }

        if let Some(user) = self.adapter.users().find_by_id(user_id).await? {
            self.send_webhook(
                WebhookEvent::PasswordChanged,
                WebhookData::User(UserWebhookData {
                    user_id: user.id,
                    email: user.email,
                    name: user.name,
                }),
            )
            .await;
        }

        Ok(())
    }
}
