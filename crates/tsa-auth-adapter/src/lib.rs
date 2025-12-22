pub mod memory;

pub use memory::*;

#[cfg(feature = "seaorm")]
pub mod seaorm;

#[cfg(feature = "redis")]
pub mod redis;

#[cfg(feature = "mongodb")]
pub mod mongodb;

#[cfg(feature = "dynamodb")]
pub mod dynamodb;

#[cfg(feature = "firestore")]
pub mod firestore;

#[cfg(feature = "bigtable")]
pub mod bigtable;

#[macro_export]
macro_rules! impl_adapter {
    ($adapter_name:ty, $prefix:ident) => {
        paste::paste! {
            impl tsa_auth_core::Adapter for $adapter_name {
                type UserRepo = [<$prefix UserRepository>];
                type SessionRepo = [<$prefix SessionRepository>];
                type AccountRepo = [<$prefix AccountRepository>];
                type VerificationTokenRepo = [<$prefix VerificationTokenRepository>];
                type TwoFactorRepo = [<$prefix TwoFactorRepository>];
                type OrganizationRepo = [<$prefix OrganizationRepository>];
                type OrganizationMemberRepo = [<$prefix OrganizationMemberRepository>];
                type OrganizationInvitationRepo = [<$prefix OrganizationInvitationRepository>];
                type ApiKeyRepo = [<$prefix ApiKeyRepository>];
                type PasskeyRepo = [<$prefix PasskeyRepository>];
                type PasskeyChallengeRepo = [<$prefix PasskeyChallengeRepository>];
                type AuditLogRepo = [<$prefix AuditLogRepository>];
                type AccountLockoutRepo = [<$prefix AccountLockoutRepository>];
                type PasswordHistoryRepo = [<$prefix PasswordHistoryRepository>];
                type IpRuleRepo = [<$prefix IpRuleRepository>];
                type ImpersonationSessionRepo = [<$prefix ImpersonationSessionRepository>];

                fn users(&self) -> &Self::UserRepo { &self.users }
                fn sessions(&self) -> &Self::SessionRepo { &self.sessions }
                fn accounts(&self) -> &Self::AccountRepo { &self.accounts }
                fn verification_tokens(&self) -> &Self::VerificationTokenRepo { &self.verification_tokens }
                fn two_factor(&self) -> &Self::TwoFactorRepo { &self.two_factor }
                fn organizations(&self) -> &Self::OrganizationRepo { &self.organizations }
                fn organization_members(&self) -> &Self::OrganizationMemberRepo { &self.organization_members }
                fn organization_invitations(&self) -> &Self::OrganizationInvitationRepo { &self.organization_invitations }
                fn api_keys(&self) -> &Self::ApiKeyRepo { &self.api_keys }
                fn passkeys(&self) -> &Self::PasskeyRepo { &self.passkeys }
                fn passkey_challenges(&self) -> &Self::PasskeyChallengeRepo { &self.passkey_challenges }
                fn audit_logs(&self) -> &Self::AuditLogRepo { &self.audit_logs }
                fn account_lockouts(&self) -> &Self::AccountLockoutRepo { &self.account_lockouts }
                fn password_history(&self) -> &Self::PasswordHistoryRepo { &self.password_history }
                fn ip_rules(&self) -> &Self::IpRuleRepo { &self.ip_rules }
                fn impersonation_sessions(&self) -> &Self::ImpersonationSessionRepo { &self.impersonation_sessions }
            }
        }
    };
}
