mod api_key;
mod authentication;
mod magic_link;
mod organization;
mod otp;
mod password;
mod session;
#[cfg(feature = "totp")]
mod two_factor;
mod verification;

use std::sync::Arc;

use chrono::Utc;
use tsa_auth_core::{
    Account, AccountRepository, Adapter, OrganizationMember, OrganizationMemberRepository,
    OrganizationRole, Result, Session, SessionRepository, TokenType, TsaError, User,
    UserRepository, VerificationToken, VerificationTokenRepository, WebhookData, WebhookEvent,
    WebhookPayload,
};
use tsa_auth_token::OpaqueToken;
use uuid::Uuid;

use crate::webhook::{NoopWebhookSender, WebhookSender};
use crate::{AuthCallbacks, AuthConfig};

pub struct Auth<A: Adapter, C: AuthCallbacks, W: WebhookSender = NoopWebhookSender> {
    pub(crate) adapter: A,
    pub(crate) config: AuthConfig,
    pub(crate) callbacks: C,
    pub(crate) webhooks: Arc<W>,
}

impl<A: Adapter, C: AuthCallbacks> Auth<A, C, NoopWebhookSender> {
    pub fn new(adapter: A, config: AuthConfig, callbacks: C) -> Self {
        Self {
            adapter,
            config,
            callbacks,
            webhooks: Arc::new(NoopWebhookSender),
        }
    }
}

impl<A: Adapter, C: AuthCallbacks, W: WebhookSender> Auth<A, C, W> {
    pub fn with_webhooks<W2: WebhookSender>(self, webhooks: W2) -> Auth<A, C, W2> {
        Auth {
            adapter: self.adapter,
            config: self.config,
            callbacks: self.callbacks,
            webhooks: Arc::new(webhooks),
        }
    }

    pub(crate) async fn send_webhook(&self, event: WebhookEvent, data: WebhookData) {
        let payload = WebhookPayload::new(event, data);
        if let Err(e) = self.webhooks.send(payload).await {
            tracing::warn!("Webhook delivery failed for {}: {}", event, e);
        }
    }

    pub(crate) async fn create_session_internal(
        &self,
        user: &User,
        ip_address: Option<String>,
        user_agent: Option<String>,
    ) -> Result<(Session, String)> {
        let (token, token_hash) =
            OpaqueToken::generate_with_hash(self.config.session_token_length)?;
        let now = Utc::now();

        let session = Session {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash,
            expires_at: now + self.config.session_expiry,
            created_at: now,
            ip_address,
            user_agent,
        };

        let session = self.adapter.sessions().create(&session).await?;
        Ok((session, token))
    }

    pub(crate) async fn send_verification_email_internal(&self, user: &User) -> Result<()> {
        let (token, token_hash) = OpaqueToken::generate_with_hash(32)?;
        let now = Utc::now();

        let verification = VerificationToken {
            id: Uuid::new_v4(),
            user_id: user.id,
            token_hash,
            token_type: TokenType::EmailVerification,
            expires_at: now + self.config.verification_token_expiry,
            created_at: now,
        };

        self.adapter
            .verification_tokens()
            .create(&verification)
            .await?;

        self.callbacks
            .send_verification_email(user, &token)
            .await?;

        Ok(())
    }

    pub(crate) async fn create_credential_account(
        &self,
        user: &User,
        password_hash: &str,
    ) -> Result<Account> {
        let now = Utc::now();
        let account = Account {
            id: Uuid::new_v4(),
            user_id: user.id,
            provider: "credential".to_string(),
            provider_account_id: user.id.to_string(),
            access_token: Some(password_hash.to_string()),
            refresh_token: None,
            expires_at: None,
            created_at: now,
        };
        self.adapter.accounts().create(&account).await
    }

    pub(crate) async fn get_password_hash(&self, account_id: Uuid) -> Result<Option<String>> {
        let accounts = self.adapter.accounts().find_by_user_id(account_id).await?;
        Ok(accounts
            .into_iter()
            .find(|a| a.provider == "credential")
            .and_then(|a| a.access_token))
    }

    pub(crate) async fn update_password_hash(
        &self,
        user_id: Uuid,
        password_hash: &str,
    ) -> Result<()> {
        let accounts = self.adapter.accounts().find_by_user_id(user_id).await?;
        if let Some(credential_account) =
            accounts.into_iter().find(|a| a.provider == "credential")
        {
            let updated = Account {
                access_token: Some(password_hash.to_string()),
                ..credential_account
            };
            self.adapter.accounts().delete(updated.id).await?;
            self.adapter.accounts().create(&updated).await?;
        }
        Ok(())
    }

    pub(crate) fn generate_otp_code() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let code: u32 = rng.gen_range(100000..1000000);
        format!("{:06}", code)
    }

    pub(crate) async fn find_users_by_phone(&self, phone: &str) -> Result<Vec<User>> {
        match self.adapter.users().find_by_phone(phone).await? {
            Some(user) => Ok(vec![user]),
            None => Ok(Vec::new()),
        }
    }

    pub(crate) async fn get_member(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
    ) -> Result<OrganizationMember> {
        self.adapter
            .organization_members()
            .find_by_org_and_user(organization_id, user_id)
            .await?
            .ok_or(TsaError::NotOrganizationMember)
    }

    pub(crate) async fn require_org_role(
        &self,
        user_id: Uuid,
        organization_id: Uuid,
        allowed_roles: &[OrganizationRole],
    ) -> Result<()> {
        let member = self.get_member(user_id, organization_id).await?;
        if !allowed_roles.contains(&member.role) {
            return Err(TsaError::InsufficientPermissions);
        }
        Ok(())
    }

    pub(crate) async fn count_owners(&self, organization_id: Uuid) -> Result<usize> {
        let members = self
            .adapter
            .organization_members()
            .find_by_organization(organization_id)
            .await?;
        Ok(members
            .iter()
            .filter(|m| m.role == OrganizationRole::Owner)
            .count())
    }
}
