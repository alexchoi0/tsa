use crate::client::FirestoreClient;
use crate::repositories::{
    FirestoreAccountLockoutRepository, FirestoreAccountRepository, FirestoreApiKeyRepository,
    FirestoreAuditLogRepository, FirestoreImpersonationSessionRepository,
    FirestoreIpRuleRepository, FirestoreOrganizationInvitationRepository,
    FirestoreOrganizationMemberRepository, FirestoreOrganizationRepository,
    FirestorePasskeyChallengeRepository, FirestorePasskeyRepository,
    FirestorePasswordHistoryRepository, FirestoreSessionRepository, FirestoreTwoFactorRepository,
    FirestoreUserRepository, FirestoreVerificationTokenRepository,
};

pub struct FirestoreAdapter {
    users: FirestoreUserRepository,
    sessions: FirestoreSessionRepository,
    accounts: FirestoreAccountRepository,
    verification_tokens: FirestoreVerificationTokenRepository,
    two_factor: FirestoreTwoFactorRepository,
    organizations: FirestoreOrganizationRepository,
    organization_members: FirestoreOrganizationMemberRepository,
    organization_invitations: FirestoreOrganizationInvitationRepository,
    api_keys: FirestoreApiKeyRepository,
    passkeys: FirestorePasskeyRepository,
    passkey_challenges: FirestorePasskeyChallengeRepository,
    audit_logs: FirestoreAuditLogRepository,
    account_lockouts: FirestoreAccountLockoutRepository,
    password_history: FirestorePasswordHistoryRepository,
    ip_rules: FirestoreIpRuleRepository,
    impersonation_sessions: FirestoreImpersonationSessionRepository,
}

impl FirestoreAdapter {
    pub fn new(client: FirestoreClient) -> Self {
        Self {
            users: FirestoreUserRepository::new(client.clone()),
            sessions: FirestoreSessionRepository::new(client.clone()),
            accounts: FirestoreAccountRepository::new(client.clone()),
            verification_tokens: FirestoreVerificationTokenRepository::new(client.clone()),
            two_factor: FirestoreTwoFactorRepository::new(client.clone()),
            organizations: FirestoreOrganizationRepository::new(client.clone()),
            organization_members: FirestoreOrganizationMemberRepository::new(client.clone()),
            organization_invitations: FirestoreOrganizationInvitationRepository::new(client.clone()),
            api_keys: FirestoreApiKeyRepository::new(client.clone()),
            passkeys: FirestorePasskeyRepository::new(client.clone()),
            passkey_challenges: FirestorePasskeyChallengeRepository::new(client.clone()),
            audit_logs: FirestoreAuditLogRepository::new(client.clone()),
            account_lockouts: FirestoreAccountLockoutRepository::new(client.clone()),
            password_history: FirestorePasswordHistoryRepository::new(client.clone()),
            ip_rules: FirestoreIpRuleRepository::new(client.clone()),
            impersonation_sessions: FirestoreImpersonationSessionRepository::new(client),
        }
    }
}

tsa_auth_adapter::impl_adapter!(FirestoreAdapter, Firestore);
