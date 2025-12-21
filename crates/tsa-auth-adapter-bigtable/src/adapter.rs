use crate::client::BigtableClient;
use crate::repositories::{
    BigtableAccountLockoutRepository, BigtableAccountRepository, BigtableApiKeyRepository,
    BigtableAuditLogRepository, BigtableImpersonationSessionRepository,
    BigtableIpRuleRepository, BigtableOrganizationInvitationRepository,
    BigtableOrganizationMemberRepository, BigtableOrganizationRepository,
    BigtablePasskeyChallengeRepository, BigtablePasskeyRepository,
    BigtablePasswordHistoryRepository, BigtableSessionRepository, BigtableTwoFactorRepository,
    BigtableUserRepository, BigtableVerificationTokenRepository,
};

pub struct BigtableAdapter {
    users: BigtableUserRepository,
    sessions: BigtableSessionRepository,
    accounts: BigtableAccountRepository,
    verification_tokens: BigtableVerificationTokenRepository,
    two_factor: BigtableTwoFactorRepository,
    organizations: BigtableOrganizationRepository,
    organization_members: BigtableOrganizationMemberRepository,
    organization_invitations: BigtableOrganizationInvitationRepository,
    api_keys: BigtableApiKeyRepository,
    passkeys: BigtablePasskeyRepository,
    passkey_challenges: BigtablePasskeyChallengeRepository,
    audit_logs: BigtableAuditLogRepository,
    account_lockouts: BigtableAccountLockoutRepository,
    password_history: BigtablePasswordHistoryRepository,
    ip_rules: BigtableIpRuleRepository,
    impersonation_sessions: BigtableImpersonationSessionRepository,
}

impl BigtableAdapter {
    pub fn new(client: BigtableClient) -> Self {
        Self {
            users: BigtableUserRepository::new(client.clone()),
            sessions: BigtableSessionRepository::new(client.clone()),
            accounts: BigtableAccountRepository::new(client.clone()),
            verification_tokens: BigtableVerificationTokenRepository::new(client.clone()),
            two_factor: BigtableTwoFactorRepository::new(client.clone()),
            organizations: BigtableOrganizationRepository::new(client.clone()),
            organization_members: BigtableOrganizationMemberRepository::new(client.clone()),
            organization_invitations: BigtableOrganizationInvitationRepository::new(client.clone()),
            api_keys: BigtableApiKeyRepository::new(client.clone()),
            passkeys: BigtablePasskeyRepository::new(client.clone()),
            passkey_challenges: BigtablePasskeyChallengeRepository::new(client.clone()),
            audit_logs: BigtableAuditLogRepository::new(client.clone()),
            account_lockouts: BigtableAccountLockoutRepository::new(client.clone()),
            password_history: BigtablePasswordHistoryRepository::new(client.clone()),
            ip_rules: BigtableIpRuleRepository::new(client.clone()),
            impersonation_sessions: BigtableImpersonationSessionRepository::new(client),
        }
    }
}

tsa_auth_adapter::impl_adapter!(BigtableAdapter, Bigtable);
