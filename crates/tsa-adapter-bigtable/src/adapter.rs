use tsa_core::Adapter;

use crate::client::BigtableClient;
use crate::repositories::{
    BigtableAccountRepository, BigtableApiKeyRepository,
    BigtableOrganizationInvitationRepository, BigtableOrganizationMemberRepository,
    BigtableOrganizationRepository, BigtablePasskeyChallengeRepository,
    BigtablePasskeyRepository, BigtableSessionRepository, BigtableTwoFactorRepository,
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
            passkey_challenges: BigtablePasskeyChallengeRepository::new(client),
        }
    }
}

impl Adapter for BigtableAdapter {
    type UserRepo = BigtableUserRepository;
    type SessionRepo = BigtableSessionRepository;
    type AccountRepo = BigtableAccountRepository;
    type VerificationTokenRepo = BigtableVerificationTokenRepository;
    type TwoFactorRepo = BigtableTwoFactorRepository;
    type OrganizationRepo = BigtableOrganizationRepository;
    type OrganizationMemberRepo = BigtableOrganizationMemberRepository;
    type OrganizationInvitationRepo = BigtableOrganizationInvitationRepository;
    type ApiKeyRepo = BigtableApiKeyRepository;
    type PasskeyRepo = BigtablePasskeyRepository;
    type PasskeyChallengeRepo = BigtablePasskeyChallengeRepository;

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
