use chrono::Utc;
use tsa_auth_core::{
    Adapter, Result, TsaError, TwoFactor, TwoFactorRepository, UserRepository, WebhookData,
    WebhookEvent, UserWebhookData,
};
use uuid::Uuid;

use crate::two_factor::{BackupCodes, TwoFactorMethod, TwoFactorSetup, TotpManager};
use crate::webhook::WebhookSender;
use crate::AuthCallbacks;

use super::Auth;

impl<A: Adapter, C: AuthCallbacks, W: WebhookSender> Auth<A, C, W> {
    pub async fn enable_2fa(&self, user_id: Uuid) -> Result<TwoFactorSetup> {
        if let Some(existing) = self.adapter.two_factor().find_by_user_id(user_id).await? {
            if existing.enabled {
                return Err(TsaError::TwoFactorAlreadyEnabled);
            }
            self.adapter.two_factor().delete(existing.id).await?;
        }

        let user = self
            .adapter
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(TsaError::UserNotFound)?;

        let totp_manager = TotpManager::new(&self.config.app_name);
        let secret = totp_manager.generate_secret();
        let otpauth_url = totp_manager.get_otpauth_url(&secret, &user.email)?;

        let backup_codes = BackupCodes::generate_default();
        let hashed_backup_codes = BackupCodes::hash_all(&backup_codes);

        let now = Utc::now();
        let two_factor = TwoFactor {
            id: Uuid::new_v4(),
            user_id,
            secret: secret.clone(),
            backup_codes: hashed_backup_codes,
            enabled: false,
            verified: false,
            created_at: now,
            updated_at: now,
        };

        self.adapter.two_factor().create(&two_factor).await?;

        Ok(TwoFactorSetup {
            secret,
            otpauth_url,
            backup_codes,
        })
    }

    pub async fn verify_2fa_setup(&self, user_id: Uuid, code: &str) -> Result<()> {
        let mut two_factor = self
            .adapter
            .two_factor()
            .find_by_user_id(user_id)
            .await?
            .ok_or(TsaError::TwoFactorNotEnabled)?;

        if two_factor.enabled {
            return Err(TsaError::TwoFactorAlreadyEnabled);
        }

        let user = self
            .adapter
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(TsaError::UserNotFound)?;

        let totp_manager = TotpManager::new(&self.config.app_name);
        if !totp_manager.verify(&two_factor.secret, code, &user.email)? {
            return Err(TsaError::InvalidTwoFactorCode);
        }

        two_factor.enabled = true;
        two_factor.verified = true;
        two_factor.updated_at = Utc::now();

        self.adapter.two_factor().update(&two_factor).await?;

        self.send_webhook(
            WebhookEvent::TwoFactorEnabled,
            WebhookData::User(UserWebhookData {
                user_id: user.id,
                email: user.email,
                name: user.name,
            }),
        )
        .await;

        Ok(())
    }

    pub async fn verify_2fa(&self, user_id: Uuid, code: &str) -> Result<TwoFactorMethod> {
        let mut two_factor = self
            .adapter
            .two_factor()
            .find_by_user_id(user_id)
            .await?
            .ok_or(TsaError::TwoFactorNotEnabled)?;

        if !two_factor.enabled {
            return Err(TsaError::TwoFactorNotEnabled);
        }

        let user = self
            .adapter
            .users()
            .find_by_id(user_id)
            .await?
            .ok_or(TsaError::UserNotFound)?;

        let totp_manager = TotpManager::new(&self.config.app_name);
        if totp_manager.verify(&two_factor.secret, code, &user.email)? {
            return Ok(TwoFactorMethod::Totp);
        }

        if let Some(index) = BackupCodes::verify(code, &two_factor.backup_codes) {
            two_factor.backup_codes.remove(index);
            two_factor.updated_at = Utc::now();
            self.adapter.two_factor().update(&two_factor).await?;
            return Ok(TwoFactorMethod::BackupCode);
        }

        Err(TsaError::InvalidTwoFactorCode)
    }

    pub async fn disable_2fa(&self, user_id: Uuid, code: &str) -> Result<()> {
        self.verify_2fa(user_id, code).await?;
        self.adapter.two_factor().delete_by_user_id(user_id).await?;

        if let Some(user) = self.adapter.users().find_by_id(user_id).await? {
            self.send_webhook(
                WebhookEvent::TwoFactorDisabled,
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

    pub async fn regenerate_backup_codes(&self, user_id: Uuid, code: &str) -> Result<Vec<String>> {
        self.verify_2fa(user_id, code).await?;

        let mut two_factor = self
            .adapter
            .two_factor()
            .find_by_user_id(user_id)
            .await?
            .ok_or(TsaError::TwoFactorNotEnabled)?;

        let backup_codes = BackupCodes::generate_default();
        let hashed_backup_codes = BackupCodes::hash_all(&backup_codes);

        two_factor.backup_codes = hashed_backup_codes;
        two_factor.updated_at = Utc::now();

        self.adapter.two_factor().update(&two_factor).await?;

        Ok(backup_codes)
    }

    pub async fn has_2fa_enabled(&self, user_id: Uuid) -> Result<bool> {
        let two_factor = self.adapter.two_factor().find_by_user_id(user_id).await?;
        Ok(two_factor.map(|t| t.enabled).unwrap_or(false))
    }

    pub async fn get_backup_codes_count(&self, user_id: Uuid) -> Result<usize> {
        let two_factor = self
            .adapter
            .two_factor()
            .find_by_user_id(user_id)
            .await?
            .ok_or(TsaError::TwoFactorNotEnabled)?;
        Ok(two_factor.backup_codes.len())
    }
}
