use chrono::Utc;
use tsa_auth_core::{
    Adapter, ApiKey, ApiKeyRepository, ApiKeyWebhookData, OrganizationRole, Result, TsaError, User,
    UserRepository, WebhookData, WebhookEvent,
};
use tsa_auth_token::OpaqueToken;
use uuid::Uuid;

use crate::webhook::WebhookSender;
use crate::AuthCallbacks;

use super::Auth;

impl<A: Adapter, C: AuthCallbacks, W: WebhookSender> Auth<A, C, W> {
    pub async fn create_api_key(
        &self,
        user_id: Uuid,
        name: &str,
        scopes: Vec<String>,
        organization_id: Option<Uuid>,
        expires_at: Option<chrono::DateTime<Utc>>,
    ) -> Result<(ApiKey, String)> {
        if let Some(org_id) = organization_id {
            self.require_org_role(
                user_id,
                org_id,
                &[OrganizationRole::Owner, OrganizationRole::Admin],
            )
            .await?;
        }

        let (key, key_hash) = OpaqueToken::generate_with_hash(32)?;
        let prefix = format!("tsa_{}", &key[..8]);

        let now = Utc::now();
        let api_key = ApiKey {
            id: Uuid::new_v4(),
            user_id,
            organization_id,
            name: name.to_string(),
            key_hash,
            prefix: prefix.clone(),
            scopes,
            expires_at,
            last_used_at: None,
            created_at: now,
        };

        let api_key = self.adapter.api_keys().create(&api_key).await?;
        let full_key = format!("{}_{}", prefix, key);

        self.send_webhook(
            WebhookEvent::ApiKeyCreated,
            WebhookData::ApiKey(ApiKeyWebhookData {
                api_key_id: api_key.id,
                user_id,
                name: api_key.name.clone(),
                prefix: Some(api_key.prefix.clone()),
            }),
        )
        .await;

        Ok((api_key, full_key))
    }

    pub async fn validate_api_key(&self, key: &str) -> Result<(ApiKey, User)> {
        if !key.starts_with("tsa_") {
            return Err(TsaError::InvalidApiKey);
        }

        let after_prefix = &key[4..];
        let parts: Vec<&str> = after_prefix.splitn(2, '_').collect();
        if parts.len() != 2 {
            return Err(TsaError::InvalidApiKey);
        }

        let key_part = parts[1];
        let key_hash = OpaqueToken::hash(key_part);

        let api_key = self
            .adapter
            .api_keys()
            .find_by_key_hash(&key_hash)
            .await?
            .ok_or(TsaError::InvalidApiKey)?;

        if let Some(expires_at) = api_key.expires_at {
            if expires_at < Utc::now() {
                return Err(TsaError::InvalidApiKey);
            }
        }

        let user = self
            .adapter
            .users()
            .find_by_id(api_key.user_id)
            .await?
            .ok_or(TsaError::UserNotFound)?;

        self.adapter.api_keys().update_last_used(api_key.id).await?;

        Ok((api_key, user))
    }

    pub async fn list_api_keys(&self, user_id: Uuid) -> Result<Vec<ApiKey>> {
        self.adapter.api_keys().find_by_user(user_id).await
    }

    pub async fn list_organization_api_keys(&self, organization_id: Uuid) -> Result<Vec<ApiKey>> {
        self.adapter
            .api_keys()
            .find_by_organization(organization_id)
            .await
    }

    pub async fn delete_api_key(&self, user_id: Uuid, api_key_id: Uuid) -> Result<()> {
        let api_key = self
            .adapter
            .api_keys()
            .find_by_id(api_key_id)
            .await?
            .ok_or(TsaError::ApiKeyNotFound)?;

        if api_key.user_id != user_id {
            if let Some(org_id) = api_key.organization_id {
                self.require_org_role(
                    user_id,
                    org_id,
                    &[OrganizationRole::Owner, OrganizationRole::Admin],
                )
                .await?;
            } else {
                return Err(TsaError::InsufficientPermissions);
            }
        }

        self.adapter.api_keys().delete(api_key_id).await?;

        self.send_webhook(
            WebhookEvent::ApiKeyRevoked,
            WebhookData::ApiKey(ApiKeyWebhookData {
                api_key_id: api_key.id,
                user_id: api_key.user_id,
                name: api_key.name,
                prefix: Some(api_key.prefix),
            }),
        )
        .await;

        Ok(())
    }

    pub async fn update_api_key(
        &self,
        user_id: Uuid,
        api_key_id: Uuid,
        name: Option<String>,
        scopes: Option<Vec<String>>,
    ) -> Result<ApiKey> {
        let mut api_key = self
            .adapter
            .api_keys()
            .find_by_id(api_key_id)
            .await?
            .ok_or(TsaError::ApiKeyNotFound)?;

        if api_key.user_id != user_id {
            if let Some(org_id) = api_key.organization_id {
                self.require_org_role(
                    user_id,
                    org_id,
                    &[OrganizationRole::Owner, OrganizationRole::Admin],
                )
                .await?;
            } else {
                return Err(TsaError::InsufficientPermissions);
            }
        }

        if let Some(name) = name {
            api_key.name = name;
        }
        if let Some(scopes) = scopes {
            api_key.scopes = scopes;
        }

        self.adapter.api_keys().update(&api_key).await
    }
}
