mod adapter;
mod client;
mod repositories;
mod schema;

pub use adapter::FirestoreAdapter;
pub use client::FirestoreClient;
pub use schema::FirestoreSchemaManager;

pub const COLLECTION_USERS: &str = "users";
pub const COLLECTION_SESSIONS: &str = "sessions";
pub const COLLECTION_ACCOUNTS: &str = "accounts";
pub const COLLECTION_VERIFICATION_TOKENS: &str = "verification_tokens";
pub const COLLECTION_TWO_FACTORS: &str = "two_factors";
pub const COLLECTION_ORGANIZATIONS: &str = "organizations";
pub const COLLECTION_ORGANIZATION_MEMBERS: &str = "organization_members";
pub const COLLECTION_ORGANIZATION_INVITATIONS: &str = "organization_invitations";
pub const COLLECTION_API_KEYS: &str = "api_keys";
pub const COLLECTION_PASSKEYS: &str = "passkeys";
pub const COLLECTION_PASSKEY_CHALLENGES: &str = "passkey_challenges";
pub const COLLECTION_AUDIT_LOGS: &str = "audit_logs";
pub const COLLECTION_ACCOUNT_LOCKOUTS: &str = "account_lockouts";
pub const COLLECTION_PASSWORD_HISTORY: &str = "password_history";
pub const COLLECTION_IP_RULES: &str = "ip_rules";
pub const COLLECTION_IMPERSONATION_SESSIONS: &str = "impersonation_sessions";
