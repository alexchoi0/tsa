# TSA - Tokens, Sessions, and Authentication

A comprehensive, modular authentication library for Rust applications. TSA provides everything you need to implement secure user authentication, session management, and organization-based access control.

## Features

- **User Authentication** - Email/password signup and signin with secure password hashing (Argon2)
- **Session Management** - Secure session tokens with configurable expiration
- **JWT Tokens** - Access and refresh token generation and validation
- **Two-Factor Authentication** - TOTP-based 2FA with backup codes
- **Passkey/WebAuthn** - Passwordless authentication support
- **OAuth 2.0** - Social login with Google, GitHub, Discord, and 10+ providers
- **Organizations** - Multi-tenant support with roles (owner, admin, member)
- **API Keys** - Scoped API key generation and validation
- **Rate Limiting** - Configurable rate limiting for auth actions
- **Enterprise RBAC** - Role-based access control with YAML configuration

## Architecture

TSA is organized as a Cargo workspace with modular crates:

```
crates/
├── tsa                    # Main crate - combines all functionality
├── tsa-core               # Core types: User, Session, Organization, errors
├── tsa-token              # JWT and opaque token generation/validation
├── tsa-session            # Session management and configuration
├── tsa-adapter            # Database adapter trait + in-memory implementation
├── tsa-oauth              # OAuth 2.0 provider registry and state management
├── tsa-enterprise         # Enterprise features: RBAC, approval workflows
├── tsa-axum               # Standalone Axum HTTP server
├── tsa-cli                # Command-line interface
│
├── tsa-adapter-seaorm     # PostgreSQL/SQLite adapter (SeaORM)
├── tsa-adapter-mongodb    # MongoDB adapter
├── tsa-adapter-redis      # Redis adapter
├── tsa-adapter-dynamodb   # AWS DynamoDB adapter
├── tsa-adapter-firestore  # Google Firestore adapter
└── tsa-adapter-bigtable   # Google Bigtable adapter
```

## Installation

Add TSA to your `Cargo.toml`:

```toml
[dependencies]
tsa = "0.1"
```

### Feature Flags

```toml
[dependencies]
tsa = { version = "0.1", features = ["oauth", "totp", "passkey", "enterprise"] }
```

| Feature | Description |
|---------|-------------|
| `oauth` | OAuth 2.0 social login (enabled by default) |
| `totp` | TOTP-based two-factor authentication (enabled by default) |
| `passkey` | WebAuthn/Passkey authentication |
| `enterprise` | RBAC and approval workflows |
| `axum` | Axum web framework integration |
| `adapter-seaorm` | PostgreSQL/SQLite support |
| `adapter-mongodb` | MongoDB support |
| `adapter-redis` | Redis support |
| `adapter-dynamodb` | AWS DynamoDB support |
| `adapter-firestore` | Google Firestore support |
| `adapter-bigtable` | Google Bigtable support |

## Quick Start

```rust
use tsa::{Auth, AuthConfig, adapter::InMemoryAdapter, NoopCallbacks};

#[tokio::main]
async fn main() -> tsa::Result<()> {
    // Create auth instance with in-memory storage
    let config = AuthConfig::builder()
        .jwt_secret("your-secret-key")
        .build();

    let adapter = InMemoryAdapter::new();
    let auth = Auth::new(config, adapter, NoopCallbacks);

    // Sign up a new user
    let (user, session, token) = auth
        .signup("user@example.com", "secure-password", Some("John Doe".to_string()))
        .await?;

    println!("User created: {}", user.email);
    println!("Session token: {}", token);

    // Sign in
    let (user, session, token) = auth
        .signin("user@example.com", "secure-password", None, None)
        .await?;

    // Validate session
    let (user, session) = auth.validate_session(&token).await?;

    // Sign out
    auth.revoke_session(session.id).await?;

    Ok(())
}
```

## CLI Usage

TSA includes a command-line interface for managing authentication:

```bash
# Start the TSA server
tsa server --port 6001

# Authentication
tsa auth signup --email user@example.com --password secret123
tsa auth signin --email user@example.com --password secret123
tsa auth signout
tsa auth status

# User management
tsa user me
tsa user update --name "John Doe"
tsa user password --current oldpass --new newpass

# Organizations
tsa org list
tsa org create --name "My Company" --slug my-company
tsa org members <org-id>
tsa org add-member <org-id> <user-id> --role admin

# Sessions
tsa session list
tsa session revoke <session-id>
tsa session revoke-all

# API Keys
tsa apikey list
tsa apikey create --name "CI Key" --scopes read,write
tsa apikey delete <key-id>

# Configuration
tsa config init
tsa config set server_url http://localhost:6001
tsa config show

# Health check
tsa health
```

## API Endpoints

The `tsa-axum` server exposes these REST endpoints:

### Authentication
- `POST /auth/signup` - Register a new user
- `POST /auth/signin` - Sign in with email/password
- `POST /auth/signout` - Sign out current session
- `POST /auth/refresh` - Refresh session
- `POST /auth/2fa/setup` - Enable 2FA
- `POST /auth/2fa/verify` - Verify 2FA code
- `DELETE /auth/2fa` - Disable 2FA
- `PUT /auth/password` - Change password

### Users
- `GET /users/me` - Get current user
- `PUT /users/me` - Update current user
- `GET /users/me/sessions` - List user sessions
- `DELETE /users/me/sessions/:id` - Revoke a session
- `DELETE /users/me/sessions` - Revoke all sessions
- `GET /users/me/api-keys` - List API keys
- `POST /users/me/api-keys` - Create API key
- `DELETE /users/me/api-keys/:id` - Delete API key

### Organizations
- `GET /organizations` - List user's organizations
- `POST /organizations` - Create organization
- `GET /organizations/:slug` - Get organization
- `PUT /organizations/:id` - Update organization
- `DELETE /organizations/:id` - Delete organization
- `GET /organizations/:id/members` - List members
- `POST /organizations/:id/members` - Add member
- `PUT /organizations/:id/members/:userId` - Update member role
- `DELETE /organizations/:id/members/:userId` - Remove member

### Health
- `GET /health` - Health check

## OAuth Configuration

```rust
use tsa::oauth::{OAuthRegistry, ProviderConfig};

let mut registry = OAuthRegistry::new("state-secret");

registry.register_google(ProviderConfig {
    client_id: "your-client-id".to_string(),
    client_secret: "your-client-secret".to_string(),
    redirect_uri: "http://localhost:3000/auth/callback/google".to_string(),
    scopes: None, // Uses defaults
});

registry.register_github(ProviderConfig {
    client_id: "your-client-id".to_string(),
    client_secret: "your-client-secret".to_string(),
    redirect_uri: "http://localhost:3000/auth/callback/github".to_string(),
    scopes: None,
});

// Get authorization URL
let (auth_url, csrf_state) = registry.authorization_url("google")?;
```

Supported providers:
- Google
- GitHub
- Discord
- Microsoft
- Apple
- Facebook
- Twitter
- LinkedIn
- Slack
- GitLab
- Twitch
- Spotify

## Enterprise RBAC

Configure role-based access control with YAML:

```yaml
roles:
  viewer:
    permissions:
      - read:documents
      - read:reports

  editor:
    inherits: [viewer]
    permissions:
      - write:documents
      - delete:documents

  admin:
    inherits: [editor]
    permissions:
      - manage:users
      - manage:settings

  superuser:
    permissions:
      - "*"

resources:
  documents:
    actions: [read, write, delete]
  reports:
    actions: [read, generate]
  users:
    actions: [read, manage]
```

```rust
use tsa::enterprise::{RbacConfig, PermissionResolver};

let config = RbacConfig::from_yaml(yaml_content)?;
let resolver = PermissionResolver::new(config);

// Check permissions
let allowed = resolver.has_permission("editor", "write:documents");
assert!(allowed);

// Get all permissions for a role
let permissions = resolver.get_all_permissions("admin");
```

## Database Adapters

### PostgreSQL (SeaORM)

```toml
[dependencies]
tsa = { version = "0.1", features = ["adapter-seaorm"] }
```

```rust
use tsa::adapter::seaorm::SeaOrmAdapter;
use sea_orm::Database;

let db = Database::connect("postgres://user:pass@localhost/tsa").await?;
let adapter = SeaOrmAdapter::new(db);
let auth = Auth::new(config, adapter, NoopCallbacks);
```

### MongoDB

```toml
[dependencies]
tsa = { version = "0.1", features = ["adapter-mongodb"] }
```

```rust
use tsa::adapter::mongodb::MongoDbAdapter;

let adapter = MongoDbAdapter::new("mongodb://localhost:27017", "tsa").await?;
let auth = Auth::new(config, adapter, NoopCallbacks);
```

### Redis

```toml
[dependencies]
tsa = { version = "0.1", features = ["adapter-redis"] }
```

```rust
use tsa::adapter::redis::RedisAdapter;

let adapter = RedisAdapter::new("redis://localhost:6379").await?;
let auth = Auth::new(config, adapter, NoopCallbacks);
```

## Testing

```bash
# Run all tests
cargo test

# Run tests for a specific crate
cargo test --package tsa

# Run with all features
cargo test --all-features
```

## License

MIT OR Apache-2.0
