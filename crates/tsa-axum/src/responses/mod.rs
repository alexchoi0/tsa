use chrono::{DateTime, Utc};
use serde::Serialize;
use tsa_core::{ApiKey, Organization, OrganizationMember, OrganizationRole, Session, User};
use uuid::Uuid;

#[derive(Serialize)]
pub struct AuthResponse {
    pub user: UserResponse,
    pub session: SessionResponse,
    pub token: String,
}

#[derive(Serialize)]
pub struct UserResponse {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub name: Option<String>,
    pub image: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<User> for UserResponse {
    fn from(user: User) -> Self {
        Self {
            id: user.id,
            email: user.email,
            email_verified: user.email_verified,
            phone: user.phone,
            phone_verified: user.phone_verified,
            name: user.name,
            image: user.image,
            created_at: user.created_at,
        }
    }
}

#[derive(Serialize)]
pub struct SessionResponse {
    pub id: Uuid,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

impl From<Session> for SessionResponse {
    fn from(session: Session) -> Self {
        Self {
            id: session.id,
            expires_at: session.expires_at,
            created_at: session.created_at,
            ip_address: session.ip_address,
            user_agent: session.user_agent,
        }
    }
}

#[derive(Serialize)]
pub struct OrganizationResponse {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub created_at: DateTime<Utc>,
}

impl From<Organization> for OrganizationResponse {
    fn from(org: Organization) -> Self {
        Self {
            id: org.id,
            name: org.name,
            slug: org.slug,
            logo: org.logo,
            role: None,
            created_at: org.created_at,
        }
    }
}

impl From<(Organization, OrganizationRole)> for OrganizationResponse {
    fn from((org, role): (Organization, OrganizationRole)) -> Self {
        Self {
            id: org.id,
            name: org.name,
            slug: org.slug,
            logo: org.logo,
            role: Some(role.to_string()),
            created_at: org.created_at,
        }
    }
}

#[derive(Serialize)]
pub struct MemberResponse {
    pub id: Uuid,
    pub user_id: Uuid,
    pub role: String,
    pub user: Option<UserResponse>,
    pub created_at: DateTime<Utc>,
}

impl From<OrganizationMember> for MemberResponse {
    fn from(member: OrganizationMember) -> Self {
        Self {
            id: member.id,
            user_id: member.user_id,
            role: member.role.to_string(),
            user: None,
            created_at: member.created_at,
        }
    }
}

impl MemberResponse {
    pub fn with_user(member: OrganizationMember, user: User) -> Self {
        Self {
            id: member.id,
            user_id: member.user_id,
            role: member.role.to_string(),
            user: Some(user.into()),
            created_at: member.created_at,
        }
    }
}

#[derive(Serialize)]
pub struct ApiKeyResponse {
    pub id: Uuid,
    pub name: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl From<ApiKey> for ApiKeyResponse {
    fn from(key: ApiKey) -> Self {
        Self {
            id: key.id,
            name: key.name,
            prefix: key.prefix,
            scopes: key.scopes,
            expires_at: key.expires_at,
            last_used_at: key.last_used_at,
            created_at: key.created_at,
        }
    }
}

#[derive(Serialize)]
pub struct ApiKeyCreatedResponse {
    pub key: ApiKeyResponse,
    pub secret: String,
}

#[derive(Serialize)]
pub struct TwoFactorSetupResponse {
    pub secret: String,
    pub otpauth_url: String,
    pub backup_codes: Vec<String>,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub message: String,
}

impl MessageResponse {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
}
