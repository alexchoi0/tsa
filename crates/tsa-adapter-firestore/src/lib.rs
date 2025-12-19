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
