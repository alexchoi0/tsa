use mongodb::Database;
use tsa_auth_core::{
    Account, ApiKey, Organization, OrganizationInvitation, OrganizationMember, Session,
    TwoFactor, User, VerificationToken,
};

use crate::repositories::{
    MongoDbAccountLockoutRepository, MongoDbAccountRepository, MongoDbApiKeyRepository,
    MongoDbAuditLogRepository, MongoDbImpersonationSessionRepository, MongoDbIpRuleRepository,
    MongoDbOrganizationInvitationRepository, MongoDbOrganizationMemberRepository,
    MongoDbOrganizationRepository, MongoDbPasskeyChallengeRepository, MongoDbPasskeyRepository,
    MongoDbPasswordHistoryRepository, MongoDbSessionRepository, MongoDbTwoFactorRepository,
    MongoDbUserRepository, MongoDbVerificationTokenRepository,
};

pub struct MongoDbAdapter {
    users: MongoDbUserRepository,
    sessions: MongoDbSessionRepository,
    accounts: MongoDbAccountRepository,
    verification_tokens: MongoDbVerificationTokenRepository,
    two_factor: MongoDbTwoFactorRepository,
    organizations: MongoDbOrganizationRepository,
    organization_members: MongoDbOrganizationMemberRepository,
    organization_invitations: MongoDbOrganizationInvitationRepository,
    api_keys: MongoDbApiKeyRepository,
    passkeys: MongoDbPasskeyRepository,
    passkey_challenges: MongoDbPasskeyChallengeRepository,
    audit_logs: MongoDbAuditLogRepository,
    account_lockouts: MongoDbAccountLockoutRepository,
    password_history: MongoDbPasswordHistoryRepository,
    ip_rules: MongoDbIpRuleRepository,
    impersonation_sessions: MongoDbImpersonationSessionRepository,
}

impl MongoDbAdapter {
    pub fn new(db: &Database) -> Self {
        Self {
            users: MongoDbUserRepository::new(db.collection::<User>("users")),
            sessions: MongoDbSessionRepository::new(db.collection::<Session>("sessions")),
            accounts: MongoDbAccountRepository::new(db.collection::<Account>("accounts")),
            verification_tokens: MongoDbVerificationTokenRepository::new(
                db.collection::<VerificationToken>("verification_tokens"),
            ),
            two_factor: MongoDbTwoFactorRepository::new(db.collection::<TwoFactor>("two_factors")),
            organizations: MongoDbOrganizationRepository::new(
                db.collection::<Organization>("organizations"),
            ),
            organization_members: MongoDbOrganizationMemberRepository::new(
                db.collection::<OrganizationMember>("organization_members"),
            ),
            organization_invitations: MongoDbOrganizationInvitationRepository::new(
                db.collection::<OrganizationInvitation>("organization_invitations"),
            ),
            api_keys: MongoDbApiKeyRepository::new(db.collection::<ApiKey>("api_keys")),
            passkeys: MongoDbPasskeyRepository::from_database(db),
            passkey_challenges: MongoDbPasskeyChallengeRepository::from_database(db),
            audit_logs: MongoDbAuditLogRepository::from_database(db),
            account_lockouts: MongoDbAccountLockoutRepository::from_database(db),
            password_history: MongoDbPasswordHistoryRepository::from_database(db),
            ip_rules: MongoDbIpRuleRepository::from_database(db),
            impersonation_sessions: MongoDbImpersonationSessionRepository::from_database(db),
        }
    }
}

tsa_auth_adapter::impl_adapter!(MongoDbAdapter, MongoDb);
