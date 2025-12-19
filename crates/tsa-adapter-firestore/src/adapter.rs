use tsa_core::Adapter;

use crate::client::FirestoreClient;
use crate::repositories::{
    FirestoreAccountRepository, FirestoreApiKeyRepository,
    FirestoreOrganizationInvitationRepository, FirestoreOrganizationMemberRepository,
    FirestoreOrganizationRepository, FirestorePasskeyChallengeRepository,
    FirestorePasskeyRepository, FirestoreSessionRepository, FirestoreTwoFactorRepository,
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
            passkey_challenges: FirestorePasskeyChallengeRepository::new(client),
        }
    }
}

impl Adapter for FirestoreAdapter {
    type UserRepo = FirestoreUserRepository;
    type SessionRepo = FirestoreSessionRepository;
    type AccountRepo = FirestoreAccountRepository;
    type VerificationTokenRepo = FirestoreVerificationTokenRepository;
    type TwoFactorRepo = FirestoreTwoFactorRepository;
    type OrganizationRepo = FirestoreOrganizationRepository;
    type OrganizationMemberRepo = FirestoreOrganizationMemberRepository;
    type OrganizationInvitationRepo = FirestoreOrganizationInvitationRepository;
    type ApiKeyRepo = FirestoreApiKeyRepository;
    type PasskeyRepo = FirestorePasskeyRepository;
    type PasskeyChallengeRepo = FirestorePasskeyChallengeRepository;

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
