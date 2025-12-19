use async_trait::async_trait;
use chrono::Utc;
use redis::aio::ConnectionManager;
use redis::AsyncCommands;
use tsa_core::{
    Account, AccountRepository, Adapter, ApiKey, ApiKeyRepository, InvitationStatus, Organization,
    OrganizationInvitation, OrganizationInvitationRepository, OrganizationMember,
    OrganizationMemberRepository, OrganizationRepository, Passkey, PasskeyChallenge,
    PasskeyChallengeRepository, PasskeyRepository, Result, Session, SessionRepository, TsaError,
    TwoFactor, TwoFactorRepository, User, UserRepository, VerificationToken,
    VerificationTokenRepository,
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
            passkey_challenges: RedisPasskeyChallengeRepository { conn },
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
