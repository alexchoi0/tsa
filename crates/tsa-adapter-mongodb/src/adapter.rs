use mongodb::Database;
use tsa_core::{
    Account, Adapter, ApiKey, Organization, OrganizationInvitation, OrganizationMember, Session,
    TwoFactor, User, VerificationToken,
};

use crate::repositories::{
    MongoDbAccountRepository, MongoDbApiKeyRepository, MongoDbOrganizationInvitationRepository,
    MongoDbOrganizationMemberRepository, MongoDbOrganizationRepository,
    MongoDbPasskeyChallengeRepository, MongoDbPasskeyRepository, MongoDbSessionRepository,
    MongoDbTwoFactorRepository, MongoDbUserRepository, MongoDbVerificationTokenRepository,
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
        }
    }
}

impl Adapter for MongoDbAdapter {
    type UserRepo = MongoDbUserRepository;
    type SessionRepo = MongoDbSessionRepository;
    type AccountRepo = MongoDbAccountRepository;
    type VerificationTokenRepo = MongoDbVerificationTokenRepository;
    type TwoFactorRepo = MongoDbTwoFactorRepository;
    type OrganizationRepo = MongoDbOrganizationRepository;
    type OrganizationMemberRepo = MongoDbOrganizationMemberRepository;
    type OrganizationInvitationRepo = MongoDbOrganizationInvitationRepository;
    type ApiKeyRepo = MongoDbApiKeyRepository;
    type PasskeyRepo = MongoDbPasskeyRepository;
    type PasskeyChallengeRepo = MongoDbPasskeyChallengeRepository;

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
