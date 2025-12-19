mod adapter;
mod repositories;
mod schema;

pub use adapter::DynamoDbAdapter;
pub use schema::DynamoDbSchemaManager;

pub const TABLE_USERS: &str = "tsa_users";
pub const TABLE_SESSIONS: &str = "tsa_sessions";
pub const TABLE_ACCOUNTS: &str = "tsa_accounts";
pub const TABLE_VERIFICATION_TOKENS: &str = "tsa_verification_tokens";
pub const TABLE_TWO_FACTORS: &str = "tsa_two_factors";
pub const TABLE_ORGANIZATIONS: &str = "tsa_organizations";
pub const TABLE_ORGANIZATION_MEMBERS: &str = "tsa_organization_members";
pub const TABLE_ORGANIZATION_INVITATIONS: &str = "tsa_organization_invitations";
pub const TABLE_API_KEYS: &str = "tsa_api_keys";
pub const TABLE_PASSKEYS: &str = "tsa_passkeys";
pub const TABLE_PASSKEY_CHALLENGES: &str = "tsa_passkey_challenges";
