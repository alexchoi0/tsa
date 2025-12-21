use chrono::Utc;
use tsa_auth_core::{
    Adapter, Result, Session, SessionRepository, TsaError, User, UserRepository, WebhookData,
    WebhookEvent, UserWebhookData, SessionWebhookData, AuthWebhookData, AccountRepository,
};
use tsa_auth_token::OpaqueToken;
use uuid::Uuid;

use crate::webhook::WebhookSender;
use crate::{AuthCallbacks, Password};

use super::Auth;

impl<A: Adapter, C: AuthCallbacks, W: WebhookSender> Auth<A, C, W> {
    pub async fn signup(
        &self,
        email: &str,
        password: &str,
        name: Option<String>,
    ) -> Result<(User, Session, String)> {
        if let Some(_existing) = self.adapter.users().find_by_email(email).await? {
            return Err(TsaError::UserAlreadyExists);
        }

        let now = Utc::now();
        let user_id = Uuid::new_v4();

        let user = User {
            id: user_id,
            email: email.to_string(),
            email_verified: false,
            phone: None,
            phone_verified: false,
            name,
            image: None,
            created_at: now,
            updated_at: now,
        };

        let user = self.adapter.users().create(&user).await?;

        let password_hash = Password::hash(password)?;
        self.create_credential_account(&user, &password_hash)
            .await?;

        let (session, token) = self.create_session_internal(&user, None, None).await?;

        self.callbacks.on_user_created(&user).await?;

        if self.config.require_email_verification {
            self.send_verification_email_internal(&user).await?;
        }

        self.send_webhook(
            WebhookEvent::UserCreated,
            WebhookData::User(UserWebhookData {
                user_id: user.id,
                email: user.email.clone(),
                name: user.name.clone(),
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

        Ok((user, session, token))
    }

    pub async fn signin(
        &self,
        email: &str,
        password: &str,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(User, Session, String)> {
        let user = self
            .adapter
            .users()
            .find_by_email(email)
            .await?
            .ok_or(TsaError::InvalidCredentials)?;

        if self.config.require_email_verification && !user.email_verified {
            self.send_verification_email_internal(&user).await?;
            return Err(TsaError::EmailNotVerified);
        }

        let accounts = self.adapter.accounts().find_by_user_id(user.id).await?;
        let _credential_account = accounts
            .iter()
            .find(|a| a.provider == "credential")
            .ok_or(TsaError::InvalidCredentials)?;

        let password_hash = self
            .get_password_hash(user.id)
            .await?
            .ok_or(TsaError::InvalidCredentials)?;

        if !Password::verify(password, &password_hash)? {
            return Err(TsaError::InvalidCredentials);
        }

        let (session, token) = self
            .create_session_internal(&user, ip_address, user_agent)
            .await?;

        self.send_webhook(
            WebhookEvent::SigninSuccess,
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

        Ok((user, session, token))
    }

    pub async fn signout(&self, session_token: &str) -> Result<()> {
        let token_hash = OpaqueToken::hash(session_token);
        if let Some(session) = self
            .adapter
            .sessions()
            .find_by_token_hash(&token_hash)
            .await?
        {
            self.adapter.sessions().delete(session.id).await?;

            self.send_webhook(
                WebhookEvent::SignoutSuccess,
                WebhookData::Session(SessionWebhookData {
                    session_id: session.id,
                    user_id: session.user_id,
                    ip_address: session.ip_address,
                    user_agent: session.user_agent,
                }),
            )
            .await;
        }
        Ok(())
    }
}
