use aws_sdk_dynamodb::Client;

use super::repositories::{
    DynamoDbAccountLockoutRepository, DynamoDbAccountRepository, DynamoDbApiKeyRepository,
    DynamoDbAuditLogRepository, DynamoDbImpersonationSessionRepository, DynamoDbIpRuleRepository,
    DynamoDbOrganizationInvitationRepository, DynamoDbOrganizationMemberRepository,
    DynamoDbOrganizationRepository, DynamoDbPasskeyChallengeRepository, DynamoDbPasskeyRepository,
    DynamoDbPasswordHistoryRepository, DynamoDbSessionRepository, DynamoDbTwoFactorRepository,
    DynamoDbUserRepository, DynamoDbVerificationTokenRepository,
};

pub struct DynamoDbAdapter {
    users: DynamoDbUserRepository,
    sessions: DynamoDbSessionRepository,
    accounts: DynamoDbAccountRepository,
    verification_tokens: DynamoDbVerificationTokenRepository,
    two_factor: DynamoDbTwoFactorRepository,
    organizations: DynamoDbOrganizationRepository,
    organization_members: DynamoDbOrganizationMemberRepository,
    organization_invitations: DynamoDbOrganizationInvitationRepository,
    api_keys: DynamoDbApiKeyRepository,
    passkeys: DynamoDbPasskeyRepository,
    passkey_challenges: DynamoDbPasskeyChallengeRepository,
    audit_logs: DynamoDbAuditLogRepository,
    account_lockouts: DynamoDbAccountLockoutRepository,
    password_history: DynamoDbPasswordHistoryRepository,
    ip_rules: DynamoDbIpRuleRepository,
    impersonation_sessions: DynamoDbImpersonationSessionRepository,
}

impl DynamoDbAdapter {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            users: DynamoDbUserRepository::new(client.clone(), table_prefix),
            sessions: DynamoDbSessionRepository::new(client.clone(), table_prefix),
            accounts: DynamoDbAccountRepository::new(client.clone(), table_prefix),
            verification_tokens: DynamoDbVerificationTokenRepository::new(
                client.clone(),
                table_prefix,
            ),
            two_factor: DynamoDbTwoFactorRepository::new(client.clone(), table_prefix),
            organizations: DynamoDbOrganizationRepository::new(client.clone(), table_prefix),
            organization_members: DynamoDbOrganizationMemberRepository::new(
                client.clone(),
                table_prefix,
            ),
            organization_invitations: DynamoDbOrganizationInvitationRepository::new(
                client.clone(),
                table_prefix,
            ),
            api_keys: DynamoDbApiKeyRepository::new(client.clone(), table_prefix),
            passkeys: DynamoDbPasskeyRepository::new(client.clone(), table_prefix),
            passkey_challenges: DynamoDbPasskeyChallengeRepository::new(
                client.clone(),
                table_prefix,
            ),
            audit_logs: DynamoDbAuditLogRepository::new(client.clone(), table_prefix),
            account_lockouts: DynamoDbAccountLockoutRepository::new(client.clone(), table_prefix),
            password_history: DynamoDbPasswordHistoryRepository::new(client.clone(), table_prefix),
            ip_rules: DynamoDbIpRuleRepository::new(client.clone(), table_prefix),
            impersonation_sessions: DynamoDbImpersonationSessionRepository::new(
                client,
                table_prefix,
            ),
        }
    }
}

crate::impl_adapter!(DynamoDbAdapter, DynamoDb);
