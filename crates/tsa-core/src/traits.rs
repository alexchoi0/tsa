use async_trait::async_trait;
use std::sync::Arc;
use uuid::Uuid;

use crate::{
    Account, ApiKey, ApprovalDecision, ApprovalRequest, ApprovalResponse, ApprovalStatus,
    ApprovalToken, InvitationStatus, Organization, OrganizationInvitation, OrganizationMember,
    Passkey, PasskeyChallenge, Result, Session, TwoFactor, User, VerificationToken,
};

#[async_trait]
pub trait SchemaManager: Send + Sync {
    async fn ensure_schema(&self) -> Result<()>;

    async fn drop_schema(&self) -> Result<()>;
}

pub trait Adapter: Send + Sync {
    type UserRepo: UserRepository;
    type SessionRepo: SessionRepository;
    type AccountRepo: AccountRepository;
    type VerificationTokenRepo: VerificationTokenRepository;
    type TwoFactorRepo: TwoFactorRepository;
    type OrganizationRepo: OrganizationRepository;
    type OrganizationMemberRepo: OrganizationMemberRepository;
    type OrganizationInvitationRepo: OrganizationInvitationRepository;
    type ApiKeyRepo: ApiKeyRepository;
    type PasskeyRepo: PasskeyRepository;
    type PasskeyChallengeRepo: PasskeyChallengeRepository;

    fn users(&self) -> &Self::UserRepo;
    fn sessions(&self) -> &Self::SessionRepo;
    fn accounts(&self) -> &Self::AccountRepo;
    fn verification_tokens(&self) -> &Self::VerificationTokenRepo;
    fn two_factor(&self) -> &Self::TwoFactorRepo;
    fn organizations(&self) -> &Self::OrganizationRepo;
    fn organization_members(&self) -> &Self::OrganizationMemberRepo;
    fn organization_invitations(&self) -> &Self::OrganizationInvitationRepo;
    fn api_keys(&self) -> &Self::ApiKeyRepo;
    fn passkeys(&self) -> &Self::PasskeyRepo;
    fn passkey_challenges(&self) -> &Self::PasskeyChallengeRepo;
}

pub type DynUserRepository = Arc<dyn UserRepository>;
pub type DynSessionRepository = Arc<dyn SessionRepository>;
pub type DynAccountRepository = Arc<dyn AccountRepository>;
pub type DynVerificationTokenRepository = Arc<dyn VerificationTokenRepository>;

#[async_trait]
pub trait UserRepository: Send + Sync {
    async fn create(&self, user: &User) -> Result<User>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<User>>;
    async fn find_by_email(&self, email: &str) -> Result<Option<User>>;
    async fn find_by_phone(&self, phone: &str) -> Result<Option<User>>;
    async fn update(&self, user: &User) -> Result<User>;
    async fn delete(&self, id: Uuid) -> Result<()>;
}

#[async_trait]
pub trait SessionRepository: Send + Sync {
    async fn create(&self, session: &Session) -> Result<Session>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Session>>;
    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<Session>>;
    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Session>>;
    async fn update(&self, session: &Session) -> Result<Session>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn delete_by_user_id(&self, user_id: Uuid) -> Result<()>;
    async fn delete_expired(&self) -> Result<u64>;
}

#[async_trait]
pub trait AccountRepository: Send + Sync {
    async fn create(&self, account: &Account) -> Result<Account>;
    async fn find_by_provider(
        &self,
        provider: &str,
        provider_account_id: &str,
    ) -> Result<Option<Account>>;
    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Vec<Account>>;
    async fn delete(&self, id: Uuid) -> Result<()>;
}

#[async_trait]
pub trait VerificationTokenRepository: Send + Sync {
    async fn create(&self, token: &VerificationToken) -> Result<VerificationToken>;
    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<VerificationToken>>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn delete_expired(&self) -> Result<u64>;
}

#[async_trait]
pub trait TwoFactorRepository: Send + Sync {
    async fn create(&self, two_factor: &TwoFactor) -> Result<TwoFactor>;
    async fn find_by_user_id(&self, user_id: Uuid) -> Result<Option<TwoFactor>>;
    async fn update(&self, two_factor: &TwoFactor) -> Result<TwoFactor>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn delete_by_user_id(&self, user_id: Uuid) -> Result<()>;
}

#[async_trait]
pub trait OrganizationRepository: Send + Sync {
    async fn create(&self, organization: &Organization) -> Result<Organization>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Organization>>;
    async fn find_by_slug(&self, slug: &str) -> Result<Option<Organization>>;
    async fn update(&self, organization: &Organization) -> Result<Organization>;
    async fn delete(&self, id: Uuid) -> Result<()>;
}

#[async_trait]
pub trait OrganizationMemberRepository: Send + Sync {
    async fn create(&self, member: &OrganizationMember) -> Result<OrganizationMember>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<OrganizationMember>>;
    async fn find_by_org_and_user(
        &self,
        organization_id: Uuid,
        user_id: Uuid,
    ) -> Result<Option<OrganizationMember>>;
    async fn find_by_organization(&self, organization_id: Uuid) -> Result<Vec<OrganizationMember>>;
    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<OrganizationMember>>;
    async fn update(&self, member: &OrganizationMember) -> Result<OrganizationMember>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn delete_by_organization(&self, organization_id: Uuid) -> Result<()>;
}

#[async_trait]
pub trait OrganizationInvitationRepository: Send + Sync {
    async fn create(&self, invitation: &OrganizationInvitation) -> Result<OrganizationInvitation>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<OrganizationInvitation>>;
    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<OrganizationInvitation>>;
    async fn find_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<OrganizationInvitation>>;
    async fn find_by_email(&self, email: &str) -> Result<Vec<OrganizationInvitation>>;
    async fn find_pending_by_org_and_email(
        &self,
        organization_id: Uuid,
        email: &str,
    ) -> Result<Option<OrganizationInvitation>>;
    async fn update(&self, invitation: &OrganizationInvitation) -> Result<OrganizationInvitation>;
    async fn update_status(&self, id: Uuid, status: InvitationStatus) -> Result<()>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn delete_expired(&self) -> Result<u64>;
}

#[async_trait]
pub trait ApiKeyRepository: Send + Sync {
    async fn create(&self, api_key: &ApiKey) -> Result<ApiKey>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<ApiKey>>;
    async fn find_by_key_hash(&self, key_hash: &str) -> Result<Option<ApiKey>>;
    async fn find_by_prefix(&self, prefix: &str) -> Result<Option<ApiKey>>;
    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<ApiKey>>;
    async fn find_by_organization(&self, organization_id: Uuid) -> Result<Vec<ApiKey>>;
    async fn update(&self, api_key: &ApiKey) -> Result<ApiKey>;
    async fn update_last_used(&self, id: Uuid) -> Result<()>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn delete_by_user(&self, user_id: Uuid) -> Result<()>;
}

#[async_trait]
pub trait PasskeyRepository: Send + Sync {
    async fn create(&self, passkey: &Passkey) -> Result<Passkey>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<Passkey>>;
    async fn find_by_credential_id(&self, credential_id: &[u8]) -> Result<Option<Passkey>>;
    async fn find_by_user(&self, user_id: Uuid) -> Result<Vec<Passkey>>;
    async fn update(&self, passkey: &Passkey) -> Result<Passkey>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn delete_by_user(&self, user_id: Uuid) -> Result<()>;
}

#[async_trait]
pub trait PasskeyChallengeRepository: Send + Sync {
    async fn create(&self, challenge: &PasskeyChallenge) -> Result<PasskeyChallenge>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<PasskeyChallenge>>;
    async fn find_by_challenge(&self, challenge: &[u8]) -> Result<Option<PasskeyChallenge>>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn delete_expired(&self) -> Result<u64>;
}

#[async_trait]
pub trait ApprovalRequestRepository: Send + Sync {
    async fn create(&self, request: &ApprovalRequest) -> Result<ApprovalRequest>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<ApprovalRequest>>;
    async fn find_by_organization(&self, organization_id: Uuid) -> Result<Vec<ApprovalRequest>>;
    async fn find_pending_by_organization(
        &self,
        organization_id: Uuid,
    ) -> Result<Vec<ApprovalRequest>>;
    async fn find_by_requester(&self, requester_id: Uuid) -> Result<Vec<ApprovalRequest>>;
    async fn update_status(
        &self,
        id: Uuid,
        status: ApprovalStatus,
        resolved_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<()>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn delete_expired(&self) -> Result<u64>;
}

#[async_trait]
pub trait ApprovalResponseRepository: Send + Sync {
    async fn create(&self, response: &ApprovalResponse) -> Result<ApprovalResponse>;
    async fn find_by_request(&self, request_id: Uuid) -> Result<Vec<ApprovalResponse>>;
    async fn count_by_request_and_decision(
        &self,
        request_id: Uuid,
        decision: ApprovalDecision,
    ) -> Result<u32>;
}

#[async_trait]
pub trait ApprovalTokenRepository: Send + Sync {
    async fn create(&self, token: &ApprovalToken) -> Result<ApprovalToken>;
    async fn find_by_id(&self, id: Uuid) -> Result<Option<ApprovalToken>>;
    async fn find_by_token_hash(&self, token_hash: &str) -> Result<Option<ApprovalToken>>;
    async fn find_by_request(&self, request_id: Uuid) -> Result<Vec<ApprovalToken>>;
    async fn mark_used(
        &self,
        id: Uuid,
        decision: ApprovalDecision,
        used_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<()>;
    async fn delete(&self, id: Uuid) -> Result<()>;
    async fn delete_by_request(&self, request_id: Uuid) -> Result<()>;
    async fn delete_expired(&self) -> Result<u64>;
}
