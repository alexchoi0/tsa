use chrono::Utc;
use tsa_auth_core::{
    Adapter, AuthWebhookData, Result, Session, SessionWebhookData, TokenType, TsaError, User,
    UserRepository, UserWebhookData, VerificationToken, VerificationTokenRepository, WebhookData,
    WebhookEvent,
};
use tsa_auth_token::OpaqueToken;
use uuid::Uuid;

use crate::webhook::WebhookSender;
use crate::AuthCallbacks;

use super::Auth;

impl<A: Adapter, C: AuthCallbacks, W: WebhookSender> Auth<A, C, W> {
    pub async fn send_email_otp(&self, email: &str) -> Result<()> {
        let user = match self.adapter.users().find_by_email(email).await? {
            Some(user) => user,
            None => return Ok(()),
        };

        let code = Self::generate_otp_code();
        let code_hash = OpaqueToken::hash(&code);
        let now = Utc::now();

        let verification = VerificationToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: code_hash,
            token_type: TokenType::EmailOtp,
            expires_at: now + self.config.otp_expiry,
            created_at: now,
        };

        self.adapter
            .verification_tokens()
            .create(&verification)
            .await?;

        self.callbacks.send_otp_email(&user, &code).await?;

        self.send_webhook(
            WebhookEvent::OtpSent,
            WebhookData::User(UserWebhookData {
                user_id: user.id,
                email: user.email,
                name: user.name,
            }),
        )
        .await;

        Ok(())
    }

    pub async fn verify_email_otp(
        &self,
        email: &str,
        code: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(User, Session, String)> {
        let user = self
            .adapter
            .users()
            .find_by_email(email)
            .await?
            .ok_or(TsaError::UserNotFound)?;

        let code_hash = OpaqueToken::hash(code);
        let verification = self
            .adapter
            .verification_tokens()
            .find_by_token_hash(&code_hash)
            .await?
            .ok_or(TsaError::InvalidToken)?;

        if verification.token_type != TokenType::EmailOtp {
            return Err(TsaError::InvalidToken);
        }

        if verification.user_id != user.id {
            return Err(TsaError::InvalidToken);
        }

        if verification.expires_at < Utc::now() {
            self.adapter
                .verification_tokens()
                .delete(verification.id)
                .await?;
            return Err(TsaError::TokenExpired);
        }

        let mut user = user;
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
            WebhookEvent::OtpVerified,
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

    pub async fn set_user_phone(&self, user_id: Uuid, phone: &str) -> Result<User> {
        let mut user = self
            .adapter
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(TsaError::UserNotFound)?;

        user.phone = Some(phone.to_string());
        user.phone_verified = false;
        user.updated_at = Utc::now();

        self.adapter.users().update(&user).await
    }

    pub async fn send_phone_otp(&self, user_id: Uuid) -> Result<()> {
        let user = self
            .adapter
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(TsaError::UserNotFound)?;

        let phone = user.phone.as_ref().ok_or(TsaError::InvalidInput(
            "User has no phone number set".to_string(),
        ))?;

        let code = Self::generate_otp_code();
        let code_hash = OpaqueToken::hash(&code);
        let now = Utc::now();

        let verification = VerificationToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: code_hash,
            token_type: TokenType::PhoneOtp,
            expires_at: now + self.config.otp_expiry,
            created_at: now,
        };

        self.adapter
            .verification_tokens()
            .create(&verification)
            .await?;

        self.callbacks.send_phone_otp(phone, &code).await?;

        self.send_webhook(
            WebhookEvent::OtpSent,
            WebhookData::User(UserWebhookData {
                user_id: user.id,
                email: user.email.clone(),
                name: user.name.clone(),
            }),
        )
        .await;

        Ok(())
    }

    pub async fn verify_phone_otp(&self, user_id: Uuid, code: &str) -> Result<User> {
        let user = self
            .adapter
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(TsaError::UserNotFound)?;

        let code_hash = OpaqueToken::hash(code);
        let verification = self
            .adapter
            .verification_tokens()
            .find_by_token_hash(&code_hash)
            .await?
            .ok_or(TsaError::InvalidToken)?;

        if verification.token_type != TokenType::PhoneOtp {
            return Err(TsaError::InvalidToken);
        }

        if verification.user_id != user.id {
            return Err(TsaError::InvalidToken);
        }

        if verification.expires_at < Utc::now() {
            self.adapter
                .verification_tokens()
                .delete(verification.id)
                .await?;
            return Err(TsaError::TokenExpired);
        }

        self.adapter
            .verification_tokens()
            .delete(verification.id)
            .await?;

        let mut user = user;
        user.phone_verified = true;
        user.updated_at = Utc::now();
        let user = self.adapter.users().update(&user).await?;

        self.send_webhook(
            WebhookEvent::PhoneVerified,
            WebhookData::User(UserWebhookData {
                user_id: user.id,
                email: user.email.clone(),
                name: user.name.clone(),
            }),
        )
        .await;

        Ok(user)
    }

    pub async fn signin_with_phone_otp(&self, phone: &str) -> Result<()> {
        let users = self.find_users_by_phone(phone).await?;

        if users.is_empty() {
            return Ok(());
        }

        let user = &users[0];

        let code = Self::generate_otp_code();
        let code_hash = OpaqueToken::hash(&code);
        let now = Utc::now();

        let verification = VerificationToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash: code_hash,
            token_type: TokenType::PhoneOtp,
            expires_at: now + self.config.otp_expiry,
            created_at: now,
        };

        self.adapter
            .verification_tokens()
            .create(&verification)
            .await?;

        self.callbacks.send_phone_otp(phone, &code).await?;

        Ok(())
    }

    pub async fn verify_phone_signin(
        &self,
        phone: &str,
        code: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(User, Session, String)> {
        let users = self.find_users_by_phone(phone).await?;

        let user = users.into_iter().next().ok_or(TsaError::UserNotFound)?;

        let code_hash = OpaqueToken::hash(code);
        let verification = self
            .adapter
            .verification_tokens()
            .find_by_token_hash(&code_hash)
            .await?
            .ok_or(TsaError::InvalidToken)?;

        if verification.token_type != TokenType::PhoneOtp {
            return Err(TsaError::InvalidToken);
        }

        if verification.user_id != user.id {
            return Err(TsaError::InvalidToken);
        }

        if verification.expires_at < Utc::now() {
            self.adapter
                .verification_tokens()
                .delete(verification.id)
                .await?;
            return Err(TsaError::TokenExpired);
        }

        self.adapter
            .verification_tokens()
            .delete(verification.id)
            .await?;

        let mut user = user;
        if !user.phone_verified {
            user.phone_verified = true;
            user.updated_at = Utc::now();
            user = self.adapter.users().update(&user).await?;
        }

        let (session, session_token) = self
            .create_session_internal(&user, ip_address, user_agent)
            .await?;

        self.send_webhook(
            WebhookEvent::OtpVerified,
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
