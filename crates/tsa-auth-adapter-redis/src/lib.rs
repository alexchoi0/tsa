use async_trait::async_trait;
use chrono::Utc;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use tsa_auth_core::{
    Account, AccountLockout, AccountLockoutRepository, AccountRepository, Adapter, ApiKey,
    ApiKeyRepository, AuditAction, AuditLog, AuditLogRepository, ImpersonationSession,
    ImpersonationSessionRepository, InvitationStatus, IpRule, IpRuleRepository, IpRuleType,
    Organization, OrganizationInvitation, OrganizationInvitationRepository, OrganizationMember,
    OrganizationMemberRepository, OrganizationRepository, Passkey, PasskeyChallenge,
    PasskeyChallengeRepository, PasskeyRepository, PasswordHistory, PasswordHistoryRepository,
    Result, Session, SessionRepository, TsaError, TwoFactor, TwoFactorRepository, User,
    UserRepository, VerificationToken, VerificationTokenRepository,
};
use uuid::Uuid;

const USER_PREFIX: &str = "tsa:user:";
const USER_EMAIL_PREFIX: &str = "tsa:user:email:";
const USER_PHONE_PREFIX: &str = "tsa:user:phone:";
const SESSION_PREFIX: &str = "tsa:session:";
const SESSION_TOKEN_PREFIX: &str = "tsa:session:token:";
const SESSION_USER_PREFIX: &str = "tsa:session:user:";
const ACCOUNT_PREFIX: &str = "tsa:account:";
const ACCOUNT_PROVIDER_PREFIX: &str = "tsa:account:provider:";
const ACCOUNT_USER_PREFIX: &str = "tsa:account:user:";
const VERIFICATION_TOKEN_PREFIX: &str = "tsa:verification:";
const VERIFICATION_TOKEN_HASH_PREFIX: &str = "tsa:verification:hash:";
const TWO_FACTOR_PREFIX: &str = "tsa:2fa:";
const TWO_FACTOR_USER_PREFIX: &str = "tsa:2fa:user:";
const ORG_PREFIX: &str = "tsa:org:";
const ORG_SLUG_PREFIX: &str = "tsa:org:slug:";
const ORG_MEMBER_PREFIX: &str = "tsa:org:member:";
const ORG_MEMBER_ORG_PREFIX: &str = "tsa:org:member:org:";
const ORG_MEMBER_USER_PREFIX: &str = "tsa:org:member:user:";
const ORG_INVITATION_PREFIX: &str = "tsa:org:invitation:";
const ORG_INVITATION_TOKEN_PREFIX: &str = "tsa:org:invitation:token:";
const ORG_INVITATION_ORG_PREFIX: &str = "tsa:org:invitation:org:";
const ORG_INVITATION_EMAIL_PREFIX: &str = "tsa:org:invitation:email:";
const API_KEY_PREFIX: &str = "tsa:apikey:";
const API_KEY_HASH_PREFIX: &str = "tsa:apikey:hash:";
const API_KEY_PREFIX_PREFIX: &str = "tsa:apikey:prefix:";
const API_KEY_USER_PREFIX: &str = "tsa:apikey:user:";
const API_KEY_ORG_PREFIX: &str = "tsa:apikey:org:";
const PASSKEY_PREFIX: &str = "tsa:passkey:";
const PASSKEY_CREDENTIAL_PREFIX: &str = "tsa:passkey:credential:";
const PASSKEY_USER_PREFIX: &str = "tsa:passkey:user:";
const PASSKEY_CHALLENGE_PREFIX: &str = "tsa:passkey:challenge:";
const PASSKEY_CHALLENGE_DATA_PREFIX: &str = "tsa:passkey:challenge:data:";
const AUDIT_LOG_PREFIX: &str = "tsa:audit:";
const AUDIT_LOG_USER_PREFIX: &str = "tsa:audit:user:";
const AUDIT_LOG_ACTION_PREFIX: &str = "tsa:audit:action:";
const AUDIT_LOG_IP_PREFIX: &str = "tsa:audit:ip:";
const AUDIT_LOG_RECENT_PREFIX: &str = "tsa:audit:recent";
const AUDIT_LOG_FAILED_PREFIX: &str = "tsa:audit:failed";
const ACCOUNT_LOCKOUT_PREFIX: &str = "tsa:lockout:";
const ACCOUNT_LOCKOUT_USER_PREFIX: &str = "tsa:lockout:user:";
const PASSWORD_HISTORY_PREFIX: &str = "tsa:password:history:";
const PASSWORD_HISTORY_USER_PREFIX: &str = "tsa:password:history:user:";
const IP_RULE_PREFIX: &str = "tsa:iprule:";
const IP_RULE_TYPE_PREFIX: &str = "tsa:iprule:type:";
const IP_RULE_ACTIVE_PREFIX: &str = "tsa:iprule:active";
const IMPERSONATION_SESSION_PREFIX: &str = "tsa:impersonation:";
const IMPERSONATION_SESSION_SESSION_PREFIX: &str = "tsa:impersonation:session:";
const IMPERSONATION_SESSION_ADMIN_PREFIX: &str = "tsa:impersonation:admin:";
const IMPERSONATION_SESSION_TARGET_PREFIX: &str = "tsa:impersonation:target:";

#[derive(Clone)]
pub struct RedisAdapter {
    users: RedisUserRepository,
    sessions: RedisSessionRepository,
    accounts: RedisAccountRepository,
    verification_tokens: RedisVerificationTokenRepository,
    two_factor: RedisTwoFactorRepository,
    organizations: RedisOrganizationRepository,
    organization_members: RedisOrganizationMemberRepository,
    organization_invitations: RedisOrganizationInvitationRepository,
    api_keys: RedisApiKeyRepository,
    passkeys: RedisPasskeyRepository,
    passkey_challenges: RedisPasskeyChallengeRepository,
    audit_logs: RedisAuditLogRepository,
    account_lockouts: RedisAccountLockoutRepository,
    password_history: RedisPasswordHistoryRepository,
    ip_rules: RedisIpRuleRepository,
    impersonation_sessions: RedisImpersonationSessionRepository,
}

impl RedisAdapter {
    pub async fn new(redis_url: &str) -> Result<Self> {
        let client =
            redis::Client::open(redis_url).map_err(|e| TsaError::Database(e.to_string()))?;
        let conn = ConnectionManager::new(client)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;
        Ok(Self::from_connection_manager(conn))
    }

    pub fn from_connection_manager(conn: ConnectionManager) -> Self {
        Self {
            users: RedisUserRepository { conn: conn.clone() },
            sessions: RedisSessionRepository { conn: conn.clone() },
            accounts: RedisAccountRepository { conn: conn.clone() },
            verification_tokens: RedisVerificationTokenRepository { conn: conn.clone() },
            two_factor: RedisTwoFactorRepository { conn: conn.clone() },
            organizations: RedisOrganizationRepository { conn: conn.clone() },
            organization_members: RedisOrganizationMemberRepository { conn: conn.clone() },
            organization_invitations: RedisOrganizationInvitationRepository { conn: conn.clone() },
            api_keys: RedisApiKeyRepository { conn: conn.clone() },
            passkeys: RedisPasskeyRepository { conn: conn.clone() },
            passkey_challenges: RedisPasskeyChallengeRepository { conn: conn.clone() },
            audit_logs: RedisAuditLogRepository { conn: conn.clone() },
            account_lockouts: RedisAccountLockoutRepository { conn: conn.clone() },
            password_history: RedisPasswordHistoryRepository { conn: conn.clone() },
            ip_rules: RedisIpRuleRepository { conn: conn.clone() },
            impersonation_sessions: RedisImpersonationSessionRepository { conn },
        }
    }
}

impl Adapter for RedisAdapter {
    type UserRepo = RedisUserRepository;
    type SessionRepo = RedisSessionRepository;
    type AccountRepo = RedisAccountRepository;
    type VerificationTokenRepo = RedisVerificationTokenRepository;
    type TwoFactorRepo = RedisTwoFactorRepository;
    type OrganizationRepo = RedisOrganizationRepository;
    type OrganizationMemberRepo = RedisOrganizationMemberRepository;
    type OrganizationInvitationRepo = RedisOrganizationInvitationRepository;
    type ApiKeyRepo = RedisApiKeyRepository;
    type PasskeyRepo = RedisPasskeyRepository;
    type PasskeyChallengeRepo = RedisPasskeyChallengeRepository;
    type AuditLogRepo = RedisAuditLogRepository;
    type AccountLockoutRepo = RedisAccountLockoutRepository;
    type PasswordHistoryRepo = RedisPasswordHistoryRepository;
    type IpRuleRepo = RedisIpRuleRepository;
    type ImpersonationSessionRepo = RedisImpersonationSessionRepository;

    fn users(&self) -> &Self::UserRepo {
        &self.users
    }

    fn sessions(&self) -> &Self::SessionRepo {
        &self.sessions
    }

    fn accounts(&self) -> &Self::AccountRepo {
        &self.accounts
    }

    fn verification_tokens(&self) -> &Self::VerificationTokenRepo {
        &self.verification_tokens
    }

    fn two_factor(&self) -> &Self::TwoFactorRepo {
        &self.two_factor
    }

    fn organizations(&self) -> &Self::OrganizationRepo {
        &self.organizations
    }

    fn organization_members(&self) -> &Self::OrganizationMemberRepo {
        &self.organization_members
    }

    fn organization_invitations(&self) -> &Self::OrganizationInvitationRepo {
        &self.organization_invitations
    }

    fn api_keys(&self) -> &Self::ApiKeyRepo {
        &self.api_keys
    }

    fn passkeys(&self) -> &Self::PasskeyRepo {
        &self.passkeys
    }

    fn passkey_challenges(&self) -> &Self::PasskeyChallengeRepo {
        &self.passkey_challenges
    }

    fn audit_logs(&self) -> &Self::AuditLogRepo {
        &self.audit_logs
    }

    fn account_lockouts(&self) -> &Self::AccountLockoutRepo {
        &self.account_lockouts
    }

    fn password_history(&self) -> &Self::PasswordHistoryRepo {
        &self.password_history
    }

    fn ip_rules(&self) -> &Self::IpRuleRepo {
        &self.ip_rules
    }

    fn impersonation_sessions(&self) -> &Self::ImpersonationSessionRepo {
        &self.impersonation_sessions
    }
}

#[derive(Clone)]
pub struct RedisUserRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl UserRepository for RedisUserRepository {
    async fn create(&self, user: &User) -> Result<User> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", USER_PREFIX, user.id);
        let email_key = format!("{}{}", USER_EMAIL_PREFIX, user.email.to_lowercase());

        let existing: Option<String> = conn
            .get(&email_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if existing.is_some() {
            return Err(TsaError::UserAlreadyExists);
        }

        let json = serde_json::to_string(user).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set(&email_key, user.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if let Some(ref phone) = user.phone {
            let phone_key = format!("{}{}", USER_PHONE_PREFIX, phone);
            let _: () = conn
                .set(&phone_key, user.id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(user.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", USER_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match json {
            Some(json) => {
                let user: User =
                    serde_json::from_str(&json).map_err(|e| TsaError::Internal(e.to_string()))?;
                Ok(Some(user))
            }
            None => Ok(None),
        }
    }

    async fn find_by_email(&self, email: &str) -> Result<Option<User>> {
        let mut conn = self.conn.clone();
        let email_key = format!("{}{}", USER_EMAIL_PREFIX, email.to_lowercase());

        let user_id: Option<String> = conn
            .get(&email_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match user_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                self.find_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn find_by_phone(&self, phone: &str) -> Result<Option<User>> {
        let mut conn = self.conn.clone();
        let phone_key = format!("{}{}", USER_PHONE_PREFIX, phone);

        let user_id: Option<String> = conn
            .get(&phone_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match user_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                self.find_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn update(&self, user: &User) -> Result<User> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", USER_PREFIX, user.id);

        let json = serde_json::to_string(user).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(user.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();

        if let Some(user) = self.find_by_id(id).await? {
            let key = format!("{}{}", USER_PREFIX, id);
            let email_key = format!("{}{}", USER_EMAIL_PREFIX, user.email.to_lowercase());

            let _: () = conn
                .del(&key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .del(&email_key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct RedisSessionRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl SessionRepository for RedisSessionRepository {
    async fn create(&self, session: &Session) -> Result<Session> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", SESSION_PREFIX, session.id);
        let token_key = format!("{}{}", SESSION_TOKEN_PREFIX, session.token_hash);
        let user_key = format!("{}{}", SESSION_USER_PREFIX, session.user_id);

        let ttl = (session.expires_at - Utc::now()).num_seconds().max(0) as u64;
        let json =
            serde_json::to_string(session).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set_ex(&key, &json, ttl)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(&token_key, session.id.to_string(), ttl)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .sadd(&user_key, session.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(session.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Session>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", SESSION_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match json {
            Some(json) => {
                let session: Session =
                    serde_json::from_str(&json).map_err(|e| TsaError::Internal(e.to_string()))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>> {
        let mut conn = self.conn.clone();
        let token_key = format!("{}{}", SESSION_TOKEN_PREFIX, token_hash);

        let session_id: Option<String> = conn
            .get(&token_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match session_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                self.find_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Session>> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", SESSION_USER_PREFIX, user_id);

        let session_ids: Vec<String> = conn
            .smembers(&user_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut sessions = Vec::new();
        for id_str in session_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(session) = self.find_by_id(id).await? {
                    sessions.push(session);
                }
            }
        }

        Ok(sessions)
    }

    async fn update(&self, session: &Session) -> Result<Session> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", SESSION_PREFIX, session.id);
        let token_key = format!("{}{}", SESSION_TOKEN_PREFIX, session.token_hash);

        let ttl = (session.expires_at - Utc::now()).num_seconds().max(0) as u64;
        let json =
            serde_json::to_string(session).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set_ex(&key, &json, ttl)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(&token_key, session.id.to_string(), ttl)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(session.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();

        if let Some(session) = self.find_by_id(id).await? {
            let key = format!("{}{}", SESSION_PREFIX, id);
            let token_key = format!("{}{}", SESSION_TOKEN_PREFIX, session.token_hash);
            let user_key = format!("{}{}", SESSION_USER_PREFIX, session.user_id);

            let _: () = conn
                .del(&key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .del(&token_key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .srem(&user_key, id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(())
    }

    async fn delete_by_user_id(&self, user_id: Uuid) -> Result<()> {
        let sessions = self.find_by_user_id(user_id).await?;
        for session in sessions {
            self.delete(session.id).await?;
        }
        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64> {
        Ok(0)
    }
}

#[derive(Clone)]
pub struct RedisAccountRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl AccountRepository for RedisAccountRepository {
    async fn create(&self, account: &Account) -> Result<Account> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ACCOUNT_PREFIX, account.id);
        let provider_key = format!(
            "{}{}:{}",
            ACCOUNT_PROVIDER_PREFIX, account.provider, account.provider_account_id
        );
        let user_key = format!("{}{}", ACCOUNT_USER_PREFIX, account.user_id);

        let json =
            serde_json::to_string(account).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set(&provider_key, account.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .sadd(&user_key, account.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(account.clone())
    }

    async fn find_by_provider(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> Result<Option<Account>> {
        let mut conn = self.conn.clone();
        let provider_key = format!("{}{}:{}", ACCOUNT_PROVIDER_PREFIX, provider, provider_account_id);

        let account_id: Option<String> = conn
            .get(&provider_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match account_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                let key = format!("{}{}", ACCOUNT_PREFIX, id);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
                match json {
                    Some(json) => {
                        let account: Account = serde_json::from_str(&json)
                            .map_err(|e| TsaError::Internal(e.to_string()))?;
                        Ok(Some(account))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Account>> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", ACCOUNT_USER_PREFIX, user_id);

        let account_ids: Vec<String> = conn
            .smembers(&user_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut accounts = Vec::new();
        for id_str in account_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                let key = format!("{}{}", ACCOUNT_PREFIX, id);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
                if let Some(json) = json {
                    if let Ok(account) = serde_json::from_str::<Account>(&json) {
                        accounts.push(account);
                    }
                }
            }
        }

        Ok(accounts)
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ACCOUNT_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if let Some(json) = json {
            if let Ok(account) = serde_json::from_str::<Account>(&json) {
                let provider_key = format!(
                    "{}{}:{}",
                    ACCOUNT_PROVIDER_PREFIX, account.provider, account.provider_account_id
                );
                let user_key = format!("{}{}", ACCOUNT_USER_PREFIX, account.user_id);

                let _: () = conn
                    .del(&key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
                let _: () = conn
                    .del(&provider_key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
                let _: () = conn
                    .srem(&user_key, id.to_string())
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct RedisVerificationTokenRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl VerificationTokenRepository for RedisVerificationTokenRepository {
    async fn create(&self, token: &VerificationToken) -> Result<VerificationToken> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", VERIFICATION_TOKEN_PREFIX, token.id);
        let hash_key = format!("{}{}", VERIFICATION_TOKEN_HASH_PREFIX, token.token_hash);

        let ttl = (token.expires_at - Utc::now()).num_seconds().max(0) as u64;
        let json = serde_json::to_string(token).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set_ex(&key, &json, ttl)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(&hash_key, token.id.to_string(), ttl)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(token.clone())
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<VerificationToken>> {
        let mut conn = self.conn.clone();
        let hash_key = format!("{}{}", VERIFICATION_TOKEN_HASH_PREFIX, token_hash);

        let token_id: Option<String> = conn
            .get(&hash_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match token_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                let key = format!("{}{}", VERIFICATION_TOKEN_PREFIX, id);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
                match json {
                    Some(json) => {
                        let token: VerificationToken = serde_json::from_str(&json)
                            .map_err(|e| TsaError::Internal(e.to_string()))?;
                        Ok(Some(token))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", VERIFICATION_TOKEN_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if let Some(json) = json {
            if let Ok(token) = serde_json::from_str::<VerificationToken>(&json) {
                let hash_key = format!("{}{}", VERIFICATION_TOKEN_HASH_PREFIX, token.token_hash);

                let _: () = conn
                    .del(&key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
                let _: () = conn
                    .del(&hash_key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
            }
        }

        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64> {
        Ok(0)
    }
}

#[derive(Clone)]
pub struct RedisTwoFactorRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl TwoFactorRepository for RedisTwoFactorRepository {
    async fn create(&self, two_factor: &TwoFactor) -> Result<TwoFactor> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", TWO_FACTOR_PREFIX, two_factor.id);
        let user_key = format!("{}{}", TWO_FACTOR_USER_PREFIX, two_factor.user_id);

        let json =
            serde_json::to_string(two_factor).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set(&user_key, two_factor.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(two_factor.clone())
    }

    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<TwoFactor>> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", TWO_FACTOR_USER_PREFIX, user_id);

        let two_factor_id: Option<String> = conn
            .get(&user_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match two_factor_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                let key = format!("{}{}", TWO_FACTOR_PREFIX, id);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
                match json {
                    Some(json) => {
                        let two_factor: TwoFactor = serde_json::from_str(&json)
                            .map_err(|e| TsaError::Internal(e.to_string()))?;
                        Ok(Some(two_factor))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    async fn update(&self, two_factor: &TwoFactor) -> Result<TwoFactor> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", TWO_FACTOR_PREFIX, two_factor.id);

        let json =
            serde_json::to_string(two_factor).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(two_factor.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", TWO_FACTOR_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if let Some(json) = json {
            if let Ok(two_factor) = serde_json::from_str::<TwoFactor>(&json) {
                let user_key = format!("{}{}", TWO_FACTOR_USER_PREFIX, two_factor.user_id);

                let _: () = conn
                    .del(&key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
                let _: () = conn
                    .del(&user_key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
            }
        }

        Ok(())
    }

    async fn delete_by_user_id(&self, user_id: Uuid) -> Result<()> {
        if let Some(two_factor) = self.find_by_user_id(user_id).await? {
            self.delete(two_factor.id).await?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RedisOrganizationRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl OrganizationRepository for RedisOrganizationRepository {
    async fn create(&self, organization: &Organization) -> Result<Organization> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORG_PREFIX, organization.id);
        let slug_key = format!("{}{}", ORG_SLUG_PREFIX, organization.slug.to_lowercase());

        let existing: Option<String> = conn
            .get(&slug_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if existing.is_some() {
            return Err(TsaError::OrganizationAlreadyExists);
        }

        let json =
            serde_json::to_string(organization).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set(&slug_key, organization.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(organization.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORG_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match json {
            Some(json) => {
                let org: Organization =
                    serde_json::from_str(&json).map_err(|e| TsaError::Internal(e.to_string()))?;
                Ok(Some(org))
            }
            None => Ok(None),
        }
    }

    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>> {
        let mut conn = self.conn.clone();
        let slug_key = format!("{}{}", ORG_SLUG_PREFIX, slug.to_lowercase());

        let org_id: Option<String> = conn
            .get(&slug_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match org_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                self.find_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn update(&self, organization: &Organization) -> Result<Organization> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORG_PREFIX, organization.id);

        let json =
            serde_json::to_string(organization).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(organization.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();

        if let Some(org) = self.find_by_id(id).await? {
            let key = format!("{}{}", ORG_PREFIX, id);
            let slug_key = format!("{}{}", ORG_SLUG_PREFIX, org.slug.to_lowercase());

            let _: () = conn
                .del(&key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .del(&slug_key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(())
    }
}

#[derive(Clone)]
pub struct RedisOrganizationMemberRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl OrganizationMemberRepository for RedisOrganizationMemberRepository {
    async fn create(&self, member: &OrganizationMember) -> Result<OrganizationMember> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORG_MEMBER_PREFIX, member.id);
        let org_key = format!("{}{}", ORG_MEMBER_ORG_PREFIX, member.organization_id);
        let user_key = format!("{}{}", ORG_MEMBER_USER_PREFIX, member.user_id);
        let unique_key = format!(
            "{}{}:{}",
            ORG_MEMBER_PREFIX, member.organization_id, member.user_id
        );

        let existing: Option<String> = conn
            .get(&unique_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if existing.is_some() {
            return Err(TsaError::AlreadyOrganizationMember);
        }

        let json = serde_json::to_string(member).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set(&unique_key, member.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .sadd(&org_key, member.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .sadd(&user_key, member.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(member.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<OrganizationMember>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORG_MEMBER_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match json {
            Some(json) => {
                let member: OrganizationMember =
                    serde_json::from_str(&json).map_err(|e| TsaError::Internal(e.to_string()))?;
                Ok(Some(member))
            }
            None => Ok(None),
        }
    }

    async fn find_by_org_and_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMember>> {
        let mut conn = self.conn.clone();
        let unique_key = format!("{}{}:{}", ORG_MEMBER_PREFIX, organization_id, user_id);

        let member_id: Option<String> = conn
            .get(&unique_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match member_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                self.find_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn find_by_organization(&self, organization_id: Uuid) -> Result<Vec<OrganizationMember>> {
        let mut conn = self.conn.clone();
        let org_key = format!("{}{}", ORG_MEMBER_ORG_PREFIX, organization_id);

        let member_ids: Vec<String> = conn
            .smembers(&org_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut members = Vec::new();
        for id_str in member_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(member) = self.find_by_id(id).await? {
                    members.push(member);
                }
            }
        }

        Ok(members)
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<OrganizationMember>> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", ORG_MEMBER_USER_PREFIX, user_id);

        let member_ids: Vec<String> = conn
            .smembers(&user_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut members = Vec::new();
        for id_str in member_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(member) = self.find_by_id(id).await? {
                    members.push(member);
                }
            }
        }

        Ok(members)
    }

    async fn update(&self, member: &OrganizationMember) -> Result<OrganizationMember> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORG_MEMBER_PREFIX, member.id);

        let json = serde_json::to_string(member).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(member.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();

        if let Some(member) = self.find_by_id(id).await? {
            let key = format!("{}{}", ORG_MEMBER_PREFIX, id);
            let org_key = format!("{}{}", ORG_MEMBER_ORG_PREFIX, member.organization_id);
            let user_key = format!("{}{}", ORG_MEMBER_USER_PREFIX, member.user_id);
            let unique_key = format!(
                "{}{}:{}",
                ORG_MEMBER_PREFIX, member.organization_id, member.user_id
            );

            let _: () = conn
                .del(&key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .del(&unique_key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .srem(&org_key, id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .srem(&user_key, id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(())
    }

    async fn delete_by_organization(&self, organization_id: Uuid) -> Result<()> {
        let members = self.find_by_organization(organization_id).await?;
        for member in members {
            self.delete(member.id).await?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RedisOrganizationInvitationRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl OrganizationInvitationRepository for RedisOrganizationInvitationRepository {
    async fn create(&self, invitation: &OrganizationInvitation) -> Result<OrganizationInvitation> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORG_INVITATION_PREFIX, invitation.id);
        let token_key = format!("{}{}", ORG_INVITATION_TOKEN_PREFIX, invitation.token_hash);
        let org_key = format!("{}{}", ORG_INVITATION_ORG_PREFIX, invitation.organization_id);
        let email_key = format!(
            "{}{}",
            ORG_INVITATION_EMAIL_PREFIX,
            invitation.email.to_lowercase()
        );

        let ttl = (invitation.expires_at - Utc::now()).num_seconds().max(0) as u64;
        let json =
            serde_json::to_string(invitation).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set_ex(&key, &json, ttl)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(&token_key, invitation.id.to_string(), ttl)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .sadd(&org_key, invitation.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .sadd(&email_key, invitation.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(invitation.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<OrganizationInvitation>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORG_INVITATION_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match json {
            Some(json) => {
                let invitation: OrganizationInvitation =
                    serde_json::from_str(&json).map_err(|e| TsaError::Internal(e.to_string()))?;
                Ok(Some(invitation))
            }
            None => Ok(None),
        }
    }

    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<OrganizationInvitation>> {
        let mut conn = self.conn.clone();
        let token_key = format!("{}{}", ORG_INVITATION_TOKEN_PREFIX, token_hash);

        let invitation_id: Option<String> = conn
            .get(&token_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match invitation_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                self.find_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn find_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationInvitation>> {
        let mut conn = self.conn.clone();
        let org_key = format!("{}{}", ORG_INVITATION_ORG_PREFIX, organization_id);

        let invitation_ids: Vec<String> = conn
            .smembers(&org_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut invitations = Vec::new();
        for id_str in invitation_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(invitation) = self.find_by_id(id).await? {
                    invitations.push(invitation);
                }
            }
        }

        Ok(invitations)
    }

    async fn find_by_email(&self, email: &str) -> Result<Vec<OrganizationInvitation>> {
        let mut conn = self.conn.clone();
        let email_key = format!("{}{}", ORG_INVITATION_EMAIL_PREFIX, email.to_lowercase());

        let invitation_ids: Vec<String> = conn
            .smembers(&email_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut invitations = Vec::new();
        for id_str in invitation_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(invitation) = self.find_by_id(id).await? {
                    invitations.push(invitation);
                }
            }
        }

        Ok(invitations)
    }

    async fn find_pending_by_org_and_email(
        &self,
        organization_id: Uuid,
        email: &str,
    ) -> Result<Option<OrganizationInvitation>> {
        let invitations = self.find_by_organization(organization_id).await?;
        Ok(invitations.into_iter().find(|i| {
            i.email.to_lowercase() == email.to_lowercase()
                && i.status == InvitationStatus::Pending
        }))
    }

    async fn update(&self, invitation: &OrganizationInvitation) -> Result<OrganizationInvitation> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ORG_INVITATION_PREFIX, invitation.id);

        let json =
            serde_json::to_string(invitation).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(invitation.clone())
    }

    async fn update_status(&self, id: Uuid, status: InvitationStatus) -> Result<()> {
        if let Some(mut invitation) = self.find_by_id(id).await? {
            invitation.status = status;
            self.update(&invitation).await?;
        }
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();

        if let Some(invitation) = self.find_by_id(id).await? {
            let key = format!("{}{}", ORG_INVITATION_PREFIX, id);
            let token_key = format!("{}{}", ORG_INVITATION_TOKEN_PREFIX, invitation.token_hash);
            let org_key = format!("{}{}", ORG_INVITATION_ORG_PREFIX, invitation.organization_id);
            let email_key = format!(
                "{}{}",
                ORG_INVITATION_EMAIL_PREFIX,
                invitation.email.to_lowercase()
            );

            let _: () = conn
                .del(&key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .del(&token_key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .srem(&org_key, id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .srem(&email_key, id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64> {
        Ok(0)
    }
}

#[derive(Clone)]
pub struct RedisApiKeyRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl ApiKeyRepository for RedisApiKeyRepository {
    async fn create(&self, api_key: &ApiKey) -> Result<ApiKey> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", API_KEY_PREFIX, api_key.id);
        let hash_key = format!("{}{}", API_KEY_HASH_PREFIX, api_key.key_hash);
        let prefix_key = format!("{}{}", API_KEY_PREFIX_PREFIX, api_key.prefix);
        let user_key = format!("{}{}", API_KEY_USER_PREFIX, api_key.user_id);

        let json = serde_json::to_string(api_key).map_err(|e| TsaError::Internal(e.to_string()))?;

        if let Some(expires_at) = api_key.expires_at {
            let ttl = (expires_at - Utc::now()).num_seconds().max(0) as u64;
            let _: () = conn
                .set_ex(&key, &json, ttl)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .set_ex(&hash_key, api_key.id.to_string(), ttl)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .set_ex(&prefix_key, api_key.id.to_string(), ttl)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        } else {
            let _: () = conn
                .set(&key, &json)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .set(&hash_key, api_key.id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .set(&prefix_key, api_key.id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        let _: () = conn
            .sadd(&user_key, api_key.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if let Some(org_id) = api_key.organization_id {
            let org_key = format!("{}{}", API_KEY_ORG_PREFIX, org_id);
            let _: () = conn
                .sadd(&org_key, api_key.id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(api_key.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<ApiKey>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", API_KEY_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match json {
            Some(json) => {
                let api_key: ApiKey =
                    serde_json::from_str(&json).map_err(|e| TsaError::Internal(e.to_string()))?;
                Ok(Some(api_key))
            }
            None => Ok(None),
        }
    }

    async fn find_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>> {
        let mut conn = self.conn.clone();
        let hash_key = format!("{}{}", API_KEY_HASH_PREFIX, key_hash);

        let api_key_id: Option<String> = conn
            .get(&hash_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match api_key_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                self.find_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn find_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>> {
        let mut conn = self.conn.clone();
        let prefix_key = format!("{}{}", API_KEY_PREFIX_PREFIX, prefix);

        let api_key_id: Option<String> = conn
            .get(&prefix_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match api_key_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                self.find_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", API_KEY_USER_PREFIX, user_id);

        let api_key_ids: Vec<String> = conn
            .smembers(&user_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut api_keys = Vec::new();
        for id_str in api_key_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(api_key) = self.find_by_id(id).await? {
                    api_keys.push(api_key);
                }
            }
        }

        Ok(api_keys)
    }

    async fn find_by_organization(&self, organization_id: Uuid) -> Result<Vec<ApiKey>> {
        let mut conn = self.conn.clone();
        let org_key = format!("{}{}", API_KEY_ORG_PREFIX, organization_id);

        let api_key_ids: Vec<String> = conn
            .smembers(&org_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut api_keys = Vec::new();
        for id_str in api_key_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(api_key) = self.find_by_id(id).await? {
                    api_keys.push(api_key);
                }
            }
        }

        Ok(api_keys)
    }

    async fn update(&self, api_key: &ApiKey) -> Result<ApiKey> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", API_KEY_PREFIX, api_key.id);

        let json = serde_json::to_string(api_key).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(api_key.clone())
    }

    async fn update_last_used(&self, id: Uuid) -> Result<()> {
        if let Some(mut api_key) = self.find_by_id(id).await? {
            api_key.last_used_at = Some(Utc::now());
            self.update(&api_key).await?;
        }
        Ok(())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();

        if let Some(api_key) = self.find_by_id(id).await? {
            let key = format!("{}{}", API_KEY_PREFIX, id);
            let hash_key = format!("{}{}", API_KEY_HASH_PREFIX, api_key.key_hash);
            let prefix_key = format!("{}{}", API_KEY_PREFIX_PREFIX, api_key.prefix);
            let user_key = format!("{}{}", API_KEY_USER_PREFIX, api_key.user_id);

            let _: () = conn
                .del(&key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .del(&hash_key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .del(&prefix_key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .srem(&user_key, id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;

            if let Some(org_id) = api_key.organization_id {
                let org_key = format!("{}{}", API_KEY_ORG_PREFIX, org_id);
                let _: () = conn
                    .srem(&org_key, id.to_string())
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
            }
        }

        Ok(())
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        let api_keys = self.find_by_user(user_id).await?;
        for api_key in api_keys {
            self.delete(api_key.id).await?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RedisPasskeyRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl PasskeyRepository for RedisPasskeyRepository {
    async fn create(&self, passkey: &Passkey) -> Result<Passkey> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", PASSKEY_PREFIX, passkey.id);
        let credential_key = format!(
            "{}{}",
            PASSKEY_CREDENTIAL_PREFIX,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &passkey.credential_id)
        );
        let user_key = format!("{}{}", PASSKEY_USER_PREFIX, passkey.user_id);

        let existing: Option<String> = conn
            .get(&credential_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if existing.is_some() {
            return Err(TsaError::PasskeyAlreadyRegistered);
        }

        let json = serde_json::to_string(passkey).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set(&credential_key, passkey.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .sadd(&user_key, passkey.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(passkey.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<Passkey>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", PASSKEY_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match json {
            Some(json) => {
                let passkey: Passkey =
                    serde_json::from_str(&json).map_err(|e| TsaError::Internal(e.to_string()))?;
                Ok(Some(passkey))
            }
            None => Ok(None),
        }
    }

    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Passkey>> {
        let mut conn = self.conn.clone();
        let credential_key = format!(
            "{}{}",
            PASSKEY_CREDENTIAL_PREFIX,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, credential_id)
        );

        let passkey_id: Option<String> = conn
            .get(&credential_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match passkey_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                self.find_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Passkey>> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", PASSKEY_USER_PREFIX, user_id);

        let passkey_ids: Vec<String> = conn
            .smembers(&user_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut passkeys = Vec::new();
        for id_str in passkey_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(passkey) = self.find_by_id(id).await? {
                    passkeys.push(passkey);
                }
            }
        }

        Ok(passkeys)
    }

    async fn update(&self, passkey: &Passkey) -> Result<Passkey> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", PASSKEY_PREFIX, passkey.id);

        let json = serde_json::to_string(passkey).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(passkey.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();

        if let Some(passkey) = self.find_by_id(id).await? {
            let key = format!("{}{}", PASSKEY_PREFIX, id);
            let credential_key = format!(
                "{}{}",
                PASSKEY_CREDENTIAL_PREFIX,
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &passkey.credential_id)
            );
            let user_key = format!("{}{}", PASSKEY_USER_PREFIX, passkey.user_id);

            let _: () = conn
                .del(&key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .del(&credential_key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .srem(&user_key, id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(())
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        let passkeys = self.find_by_user(user_id).await?;
        for passkey in passkeys {
            self.delete(passkey.id).await?;
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct RedisPasskeyChallengeRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl PasskeyChallengeRepository for RedisPasskeyChallengeRepository {
    async fn create(&self, challenge: &PasskeyChallenge) -> Result<PasskeyChallenge> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", PASSKEY_CHALLENGE_PREFIX, challenge.id);
        let data_key = format!(
            "{}{}",
            PASSKEY_CHALLENGE_DATA_PREFIX,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &challenge.challenge)
        );

        let ttl = (challenge.expires_at - Utc::now()).num_seconds().max(0) as u64;
        let json =
            serde_json::to_string(challenge).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set_ex(&key, &json, ttl)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set_ex(&data_key, challenge.id.to_string(), ttl)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(challenge.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<PasskeyChallenge>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", PASSKEY_CHALLENGE_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match json {
            Some(json) => {
                let challenge: PasskeyChallenge =
                    serde_json::from_str(&json).map_err(|e| TsaError::Internal(e.to_string()))?;
                Ok(Some(challenge))
            }
            None => Ok(None),
        }
    }

    async fn find_by_challenge(&self, challenge: &[u8]) -> Result<Option<PasskeyChallenge>> {
        let mut conn = self.conn.clone();
        let data_key = format!(
            "{}{}",
            PASSKEY_CHALLENGE_DATA_PREFIX,
            base64::Engine::encode(&base64::engine::general_purpose::STANDARD, challenge)
        );

        let challenge_id: Option<String> = conn
            .get(&data_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match challenge_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                self.find_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();

        if let Some(challenge) = self.find_by_id(id).await? {
            let key = format!("{}{}", PASSKEY_CHALLENGE_PREFIX, id);
            let data_key = format!(
                "{}{}",
                PASSKEY_CHALLENGE_DATA_PREFIX,
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, &challenge.challenge)
            );

            let _: () = conn
                .del(&key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .del(&data_key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64> {
        Ok(0)
    }
}

#[derive(Clone)]
pub struct RedisAuditLogRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl AuditLogRepository for RedisAuditLogRepository {
    async fn create(&self, log: &AuditLog) -> Result<AuditLog> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", AUDIT_LOG_PREFIX, log.id);

        let json = serde_json::to_string(log).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if let Some(user_id) = log.user_id {
            let user_key = format!("{}{}", AUDIT_LOG_USER_PREFIX, user_id);
            let _: () = conn
                .zadd(&user_key, log.id.to_string(), log.created_at.timestamp())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        let action_key = format!("{}{:?}", AUDIT_LOG_ACTION_PREFIX, log.action);
        let _: () = conn
            .zadd(&action_key, log.id.to_string(), log.created_at.timestamp())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if let Some(ref ip) = log.ip_address {
            let ip_key = format!("{}{}", AUDIT_LOG_IP_PREFIX, ip);
            let _: () = conn
                .zadd(&ip_key, log.id.to_string(), log.created_at.timestamp())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        let _: () = conn
            .zadd(AUDIT_LOG_RECENT_PREFIX, log.id.to_string(), log.created_at.timestamp())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if !log.success {
            let _: () = conn
                .zadd(AUDIT_LOG_FAILED_PREFIX, log.id.to_string(), log.created_at.timestamp())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(log.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<AuditLog>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", AUDIT_LOG_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match json {
            Some(json) => {
                let log: AuditLog =
                    serde_json::from_str(&json).map_err(|e| TsaError::Internal(e.to_string()))?;
                Ok(Some(log))
            }
            None => Ok(None),
        }
    }

    async fn find_by_user(&self, user_id: Uuid, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", AUDIT_LOG_USER_PREFIX, user_id);

        let log_ids: Vec<String> = conn
            .zrevrange(&user_key, offset as isize, (offset + limit - 1) as isize)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for id_str in log_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(log) = self.find_by_id(id).await? {
                    logs.push(log);
                }
            }
        }

        Ok(logs)
    }

    async fn find_by_action(
        &self,
        action: AuditAction,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<AuditLog>> {
        let mut conn = self.conn.clone();
        let action_key = format!("{}{:?}", AUDIT_LOG_ACTION_PREFIX, action);

        let log_ids: Vec<String> = conn
            .zrevrange(&action_key, offset as isize, (offset + limit - 1) as isize)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for id_str in log_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(log) = self.find_by_id(id).await? {
                    logs.push(log);
                }
            }
        }

        Ok(logs)
    }

    async fn find_by_ip(&self, ip_address: &str, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let mut conn = self.conn.clone();
        let ip_key = format!("{}{}", AUDIT_LOG_IP_PREFIX, ip_address);

        let log_ids: Vec<String> = conn
            .zrevrange(&ip_key, offset as isize, (offset + limit - 1) as isize)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for id_str in log_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(log) = self.find_by_id(id).await? {
                    logs.push(log);
                }
            }
        }

        Ok(logs)
    }

    async fn find_recent(&self, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let mut conn = self.conn.clone();

        let log_ids: Vec<String> = conn
            .zrevrange(AUDIT_LOG_RECENT_PREFIX, offset as isize, (offset + limit - 1) as isize)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for id_str in log_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(log) = self.find_by_id(id).await? {
                    logs.push(log);
                }
            }
        }

        Ok(logs)
    }

    async fn find_failed(&self, limit: u32, offset: u32) -> Result<Vec<AuditLog>> {
        let mut conn = self.conn.clone();

        let log_ids: Vec<String> = conn
            .zrevrange(AUDIT_LOG_FAILED_PREFIX, offset as isize, (offset + limit - 1) as isize)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut logs = Vec::new();
        for id_str in log_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(log) = self.find_by_id(id).await? {
                    logs.push(log);
                }
            }
        }

        Ok(logs)
    }

    async fn count_by_user(&self, user_id: Uuid) -> Result<u64> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", AUDIT_LOG_USER_PREFIX, user_id);

        let count: u64 = conn
            .zcard(&user_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(count)
    }

    async fn count_failed_by_user_since(
        &self,
        user_id: Uuid,
        since: chrono::DateTime<chrono::Utc>,
    ) -> Result<u32> {
        let logs = self.find_by_user(user_id, 1000, 0).await?;
        let count = logs
            .iter()
            .filter(|log| !log.success && log.created_at >= since)
            .count() as u32;
        Ok(count)
    }

    async fn delete_older_than(&self, before: chrono::DateTime<chrono::Utc>) -> Result<u64> {
        let mut conn = self.conn.clone();
        let timestamp = before.timestamp();

        let _: () = conn
            .zrembyscore(AUDIT_LOG_RECENT_PREFIX, "-inf", timestamp)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .zrembyscore(AUDIT_LOG_FAILED_PREFIX, "-inf", timestamp)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(0)
    }
}

#[derive(Clone)]
pub struct RedisAccountLockoutRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl AccountLockoutRepository for RedisAccountLockoutRepository {
    async fn create(&self, lockout: &AccountLockout) -> Result<AccountLockout> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ACCOUNT_LOCKOUT_PREFIX, lockout.id);
        let user_key = format!("{}{}", ACCOUNT_LOCKOUT_USER_PREFIX, lockout.user_id);

        let json =
            serde_json::to_string(lockout).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set(&user_key, lockout.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(lockout.clone())
    }

    async fn find_by_user(&self, user_id: Uuid) -> Result<Option<AccountLockout>> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", ACCOUNT_LOCKOUT_USER_PREFIX, user_id);

        let lockout_id: Option<String> = conn
            .get(&user_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match lockout_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                let key = format!("{}{}", ACCOUNT_LOCKOUT_PREFIX, id);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
                match json {
                    Some(json) => {
                        let lockout: AccountLockout = serde_json::from_str(&json)
                            .map_err(|e| TsaError::Internal(e.to_string()))?;
                        Ok(Some(lockout))
                    }
                    None => Ok(None),
                }
            }
            None => Ok(None),
        }
    }

    async fn update(&self, lockout: &AccountLockout) -> Result<AccountLockout> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ACCOUNT_LOCKOUT_PREFIX, lockout.id);

        let json =
            serde_json::to_string(lockout).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(lockout.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", ACCOUNT_LOCKOUT_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        if let Some(json) = json {
            if let Ok(lockout) = serde_json::from_str::<AccountLockout>(&json) {
                let user_key = format!("{}{}", ACCOUNT_LOCKOUT_USER_PREFIX, lockout.user_id);

                let _: () = conn
                    .del(&key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
                let _: () = conn
                    .del(&user_key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
            }
        }

        Ok(())
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        if let Some(lockout) = self.find_by_user(user_id).await? {
            self.delete(lockout.id).await?;
        }
        Ok(())
    }

    async fn increment_failed_attempts(&self, user_id: Uuid) -> Result<AccountLockout> {
        let now = Utc::now();

        if let Some(mut lockout) = self.find_by_user(user_id).await? {
            lockout.failed_attempts += 1;
            lockout.last_failed_at = Some(now);
            lockout.updated_at = now;
            self.update(&lockout).await
        } else {
            let lockout = AccountLockout {
                id: Uuid::new_v4(),
                user_id,
                failed_attempts: 1,
                locked_until: None,
                last_failed_at: Some(now),
                created_at: now,
                updated_at: now,
            };
            self.create(&lockout).await
        }
    }

    async fn reset_failed_attempts(&self, user_id: Uuid) -> Result<()> {
        self.delete_by_user(user_id).await
    }
}

#[derive(Clone)]
pub struct RedisPasswordHistoryRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl PasswordHistoryRepository for RedisPasswordHistoryRepository {
    async fn create(&self, history: &PasswordHistory) -> Result<PasswordHistory> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", PASSWORD_HISTORY_PREFIX, history.id);
        let user_key = format!("{}{}", PASSWORD_HISTORY_USER_PREFIX, history.user_id);

        let json =
            serde_json::to_string(history).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .zadd(&user_key, history.id.to_string(), history.created_at.timestamp())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(history.clone())
    }

    async fn find_by_user(&self, user_id: Uuid, limit: u32) -> Result<Vec<PasswordHistory>> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", PASSWORD_HISTORY_USER_PREFIX, user_id);

        let history_ids: Vec<String> = conn
            .zrevrange(&user_key, 0, (limit - 1) as isize)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut histories = Vec::new();
        for id_str in history_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                let key = format!("{}{}", PASSWORD_HISTORY_PREFIX, id);
                let json: Option<String> = conn
                    .get(&key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
                if let Some(json) = json {
                    if let Ok(history) = serde_json::from_str::<PasswordHistory>(&json) {
                        histories.push(history);
                    }
                }
            }
        }

        Ok(histories)
    }

    async fn delete_old_entries(&self, user_id: Uuid, keep_count: u32) -> Result<u64> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", PASSWORD_HISTORY_USER_PREFIX, user_id);

        let all_ids: Vec<String> = conn
            .zrevrange(&user_key, 0, -1)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let to_delete: Vec<String> = all_ids.into_iter().skip(keep_count as usize).collect();
        let count = to_delete.len() as u64;

        for id_str in to_delete {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                let key = format!("{}{}", PASSWORD_HISTORY_PREFIX, id);
                let _: () = conn
                    .del(&key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
                let _: () = conn
                    .zrem(&user_key, &id_str)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
            }
        }

        Ok(count)
    }

    async fn delete_by_user(&self, user_id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();
        let user_key = format!("{}{}", PASSWORD_HISTORY_USER_PREFIX, user_id);

        let history_ids: Vec<String> = conn
            .zrevrange(&user_key, 0, -1)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        for id_str in history_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                let key = format!("{}{}", PASSWORD_HISTORY_PREFIX, id);
                let _: () = conn
                    .del(&key)
                    .await
                    .map_err(|e| TsaError::Database(e.to_string()))?;
            }
        }

        let _: () = conn
            .del(&user_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(())
    }
}

#[derive(Clone)]
pub struct RedisIpRuleRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl IpRuleRepository for RedisIpRuleRepository {
    async fn create(&self, rule: &IpRule) -> Result<IpRule> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", IP_RULE_PREFIX, rule.id);
        let type_key = format!("{}{:?}", IP_RULE_TYPE_PREFIX, rule.rule_type);

        let json = serde_json::to_string(rule).map_err(|e| TsaError::Internal(e.to_string()))?;

        if let Some(expires_at) = rule.expires_at {
            let ttl = (expires_at - Utc::now()).num_seconds().max(0) as u64;
            let _: () = conn
                .set_ex(&key, &json, ttl)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        } else {
            let _: () = conn
                .set(&key, &json)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        let _: () = conn
            .sadd(&type_key, rule.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .sadd(IP_RULE_ACTIVE_PREFIX, rule.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(rule.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<IpRule>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", IP_RULE_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match json {
            Some(json) => {
                let rule: IpRule =
                    serde_json::from_str(&json).map_err(|e| TsaError::Internal(e.to_string()))?;
                Ok(Some(rule))
            }
            None => Ok(None),
        }
    }

    async fn find_all(&self) -> Result<Vec<IpRule>> {
        let mut conn = self.conn.clone();

        let rule_ids: Vec<String> = conn
            .smembers(IP_RULE_ACTIVE_PREFIX)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut rules = Vec::new();
        for id_str in rule_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(rule) = self.find_by_id(id).await? {
                    rules.push(rule);
                }
            }
        }

        Ok(rules)
    }

    async fn find_by_type(&self, rule_type: IpRuleType) -> Result<Vec<IpRule>> {
        let mut conn = self.conn.clone();
        let type_key = format!("{}{:?}", IP_RULE_TYPE_PREFIX, rule_type);

        let rule_ids: Vec<String> = conn
            .smembers(&type_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut rules = Vec::new();
        for id_str in rule_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(rule) = self.find_by_id(id).await? {
                    rules.push(rule);
                }
            }
        }

        Ok(rules)
    }

    async fn find_active(&self) -> Result<Vec<IpRule>> {
        self.find_all().await
    }

    async fn update(&self, rule: &IpRule) -> Result<IpRule> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", IP_RULE_PREFIX, rule.id);

        let json = serde_json::to_string(rule).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(rule.clone())
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();

        if let Some(rule) = self.find_by_id(id).await? {
            let key = format!("{}{}", IP_RULE_PREFIX, id);
            let type_key = format!("{}{:?}", IP_RULE_TYPE_PREFIX, rule.rule_type);

            let _: () = conn
                .del(&key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .srem(&type_key, id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .srem(IP_RULE_ACTIVE_PREFIX, id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(())
    }

    async fn delete_expired(&self) -> Result<u64> {
        Ok(0)
    }
}

#[derive(Clone)]
pub struct RedisImpersonationSessionRepository {
    conn: ConnectionManager,
}

#[async_trait]
impl ImpersonationSessionRepository for RedisImpersonationSessionRepository {
    async fn create(&self, session: &ImpersonationSession) -> Result<ImpersonationSession> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", IMPERSONATION_SESSION_PREFIX, session.id);
        let session_key = format!(
            "{}{}",
            IMPERSONATION_SESSION_SESSION_PREFIX, session.impersonation_session_id
        );
        let admin_key = format!("{}{}", IMPERSONATION_SESSION_ADMIN_PREFIX, session.admin_id);
        let target_key = format!(
            "{}{}",
            IMPERSONATION_SESSION_TARGET_PREFIX, session.target_user_id
        );

        let json =
            serde_json::to_string(session).map_err(|e| TsaError::Internal(e.to_string()))?;

        let _: () = conn
            .set(&key, &json)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .set(&session_key, session.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .sadd(&admin_key, session.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let _: () = conn
            .sadd(&target_key, session.id.to_string())
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        Ok(session.clone())
    }

    async fn find_by_id(&self, id: Uuid) -> Result<Option<ImpersonationSession>> {
        let mut conn = self.conn.clone();
        let key = format!("{}{}", IMPERSONATION_SESSION_PREFIX, id);

        let json: Option<String> = conn
            .get(&key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match json {
            Some(json) => {
                let session: ImpersonationSession =
                    serde_json::from_str(&json).map_err(|e| TsaError::Internal(e.to_string()))?;
                Ok(Some(session))
            }
            None => Ok(None),
        }
    }

    async fn find_by_session_id(&self, session_id: Uuid) -> Result<Option<ImpersonationSession>> {
        let mut conn = self.conn.clone();
        let session_key = format!("{}{}", IMPERSONATION_SESSION_SESSION_PREFIX, session_id);

        let impersonation_id: Option<String> = conn
            .get(&session_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        match impersonation_id {
            Some(id) => {
                let id = Uuid::parse_str(&id).map_err(|e| TsaError::Internal(e.to_string()))?;
                self.find_by_id(id).await
            }
            None => Ok(None),
        }
    }

    async fn find_active_by_admin(&self, admin_id: Uuid) -> Result<Vec<ImpersonationSession>> {
        let mut conn = self.conn.clone();
        let admin_key = format!("{}{}", IMPERSONATION_SESSION_ADMIN_PREFIX, admin_id);

        let session_ids: Vec<String> = conn
            .smembers(&admin_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut sessions = Vec::new();
        for id_str in session_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(session) = self.find_by_id(id).await? {
                    if session.ended_at.is_none() {
                        sessions.push(session);
                    }
                }
            }
        }

        Ok(sessions)
    }

    async fn find_by_target_user(&self, target_user_id: Uuid) -> Result<Vec<ImpersonationSession>> {
        let mut conn = self.conn.clone();
        let target_key = format!("{}{}", IMPERSONATION_SESSION_TARGET_PREFIX, target_user_id);

        let session_ids: Vec<String> = conn
            .smembers(&target_key)
            .await
            .map_err(|e| TsaError::Database(e.to_string()))?;

        let mut sessions = Vec::new();
        for id_str in session_ids {
            if let Ok(id) = Uuid::parse_str(&id_str) {
                if let Some(session) = self.find_by_id(id).await? {
                    sessions.push(session);
                }
            }
        }

        Ok(sessions)
    }

    async fn end_session(
        &self,
        id: Uuid,
        ended_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<ImpersonationSession> {
        if let Some(mut session) = self.find_by_id(id).await? {
            session.ended_at = Some(ended_at);
            let mut conn = self.conn.clone();
            let key = format!("{}{}", IMPERSONATION_SESSION_PREFIX, id);

            let json =
                serde_json::to_string(&session).map_err(|e| TsaError::Internal(e.to_string()))?;

            let _: () = conn
                .set(&key, &json)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;

            Ok(session)
        } else {
            Err(TsaError::Internal("Impersonation session not found".to_string()))
        }
    }

    async fn delete(&self, id: Uuid) -> Result<()> {
        let mut conn = self.conn.clone();

        if let Some(session) = self.find_by_id(id).await? {
            let key = format!("{}{}", IMPERSONATION_SESSION_PREFIX, id);
            let session_key = format!(
                "{}{}",
                IMPERSONATION_SESSION_SESSION_PREFIX, session.impersonation_session_id
            );
            let admin_key = format!("{}{}", IMPERSONATION_SESSION_ADMIN_PREFIX, session.admin_id);
            let target_key = format!(
                "{}{}",
                IMPERSONATION_SESSION_TARGET_PREFIX, session.target_user_id
            );

            let _: () = conn
                .del(&key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .del(&session_key)
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .srem(&admin_key, id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
            let _: () = conn
                .srem(&target_key, id.to_string())
                .await
                .map_err(|e| TsaError::Database(e.to_string()))?;
        }

        Ok(())
    }
}
