use aws_sdk_dynamodb::Client;
use tsa_core::Adapter;

use crate::repositories::{
    DynamoDbAccountRepository, DynamoDbApiKeyRepository, DynamoDbOrganizationInvitationRepository,
    DynamoDbOrganizationMemberRepository, DynamoDbOrganizationRepository,
    DynamoDbPasskeyChallengeRepository, DynamoDbPasskeyRepository, DynamoDbSessionRepository,
    DynamoDbTwoFactorRepository, DynamoDbUserRepository, DynamoDbVerificationTokenRepository,
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
}

impl DynamoDbAdapter {
    pub fn new(client: Client, table_prefix: &str) -> Self {
        Self {
            users: DynamoDbUserRepository::new(client.clone(), table_prefix),
            sessions: DynamoDbSessionRepository::new(client.clone(), table_prefix),
            accounts: DynamoDbAccountRepository::new(client.clone(), table_prefix),
            verification_tokens: DynamoDbVerificationTokenRepository::new(client.clone(), table_prefix),
            two_factor: DynamoDbTwoFactorRepository::new(client.clone(), table_prefix),
            organizations: DynamoDbOrganizationRepository::new(client.clone(), table_prefix),
            organization_members: DynamoDbOrganizationMemberRepository::new(client.clone(), table_prefix),
            organization_invitations: DynamoDbOrganizationInvitationRepository::new(client.clone(), table_prefix),
            api_keys: DynamoDbApiKeyRepository::new(client.clone(), table_prefix),
            passkeys: DynamoDbPasskeyRepository::new(client.clone(), table_prefix),
            passkey_challenges: DynamoDbPasskeyChallengeRepository::new(client, table_prefix),
        }
    }
}

impl Adapter for DynamoDbAdapter {
    type UserRepo = DynamoDbUserRepository;
    type SessionRepo = DynamoDbSessionRepository;
    type AccountRepo = DynamoDbAccountRepository;
    type VerificationTokenRepo = DynamoDbVerificationTokenRepository;
    type TwoFactorRepo = DynamoDbTwoFactorRepository;
    type OrganizationRepo = DynamoDbOrganizationRepository;
    type OrganizationMemberRepo = DynamoDbOrganizationMemberRepository;
    type OrganizationInvitationRepo = DynamoDbOrganizationInvitationRepository;
    type ApiKeyRepo = DynamoDbApiKeyRepository;
    type PasskeyRepo = DynamoDbPasskeyRepository;
    type PasskeyChallengeRepo = DynamoDbPasskeyChallengeRepository;

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
