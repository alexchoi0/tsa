mod generated;

pub use generated::*;

use chrono::{DateTime, TimeZone, Utc};
use prost_types::Timestamp;
use tsa_auth_core::types as core;
use uuid::Uuid;

pub fn timestamp_to_datetime(ts: Option<Timestamp>) -> DateTime<Utc> {
    ts.map(|t| Utc.timestamp_opt(t.seconds, t.nanos as u32).unwrap())
        .unwrap_or_else(Utc::now)
}

pub fn datetime_to_timestamp(dt: DateTime<Utc>) -> Timestamp {
    Timestamp {
        seconds: dt.timestamp(),
        nanos: dt.timestamp_subsec_nanos() as i32,
    }
}

pub fn optional_timestamp(dt: Option<DateTime<Utc>>) -> Option<Timestamp> {
    dt.map(datetime_to_timestamp)
}

impl From<core::User> for User {
    fn from(u: core::User) -> Self {
        User {
            id: u.id.to_string(),
            email: u.email,
            email_verified: u.email_verified,
            phone: u.phone,
            phone_verified: u.phone_verified,
            name: u.name,
            image: u.image,
            created_at: Some(datetime_to_timestamp(u.created_at)),
            updated_at: Some(datetime_to_timestamp(u.updated_at)),
        }
    }
}

impl TryFrom<User> for core::User {
    type Error = &'static str;

    fn try_from(u: User) -> Result<Self, Self::Error> {
        Ok(core::User {
            id: Uuid::parse_str(&u.id).map_err(|_| "Invalid user id")?,
            email: u.email,
            email_verified: u.email_verified,
            phone: u.phone,
            phone_verified: u.phone_verified,
            name: u.name,
            image: u.image,
            created_at: timestamp_to_datetime(u.created_at),
            updated_at: timestamp_to_datetime(u.updated_at),
        })
    }
}

impl From<core::Session> for Session {
    fn from(s: core::Session) -> Self {
        Session {
            id: s.id.to_string(),
            user_id: s.user_id.to_string(),
            expires_at: Some(datetime_to_timestamp(s.expires_at)),
            created_at: Some(datetime_to_timestamp(s.created_at)),
            ip_address: s.ip_address,
            user_agent: s.user_agent,
        }
    }
}

impl TryFrom<Session> for core::Session {
    type Error = &'static str;

    fn try_from(s: Session) -> Result<Self, Self::Error> {
        Ok(core::Session {
            id: Uuid::parse_str(&s.id).map_err(|_| "Invalid session id")?,
            user_id: Uuid::parse_str(&s.user_id).map_err(|_| "Invalid user id")?,
            token_hash: String::new(),
            expires_at: timestamp_to_datetime(s.expires_at),
            created_at: timestamp_to_datetime(s.created_at),
            ip_address: s.ip_address,
            user_agent: s.user_agent,
        })
    }
}

impl From<core::Organization> for Organization {
    fn from(o: core::Organization) -> Self {
        Organization {
            id: o.id.to_string(),
            name: o.name,
            slug: o.slug,
            logo: o.logo,
            role: None,
            created_at: Some(datetime_to_timestamp(o.created_at)),
            updated_at: Some(datetime_to_timestamp(o.updated_at)),
        }
    }
}

impl TryFrom<Organization> for core::Organization {
    type Error = &'static str;

    fn try_from(o: Organization) -> Result<Self, Self::Error> {
        Ok(core::Organization {
            id: Uuid::parse_str(&o.id).map_err(|_| "Invalid organization id")?,
            name: o.name,
            slug: o.slug,
            logo: o.logo,
            metadata: None,
            created_at: timestamp_to_datetime(o.created_at),
            updated_at: timestamp_to_datetime(o.updated_at),
        })
    }
}

pub fn organization_with_role(
    o: core::Organization,
    role: Option<core::OrganizationRole>,
) -> Organization {
    Organization {
        id: o.id.to_string(),
        name: o.name,
        slug: o.slug,
        logo: o.logo,
        role: role.map(|r| r.to_string()),
        created_at: Some(datetime_to_timestamp(o.created_at)),
        updated_at: Some(datetime_to_timestamp(o.updated_at)),
    }
}

impl From<core::OrganizationMember> for Member {
    fn from(m: core::OrganizationMember) -> Self {
        Member {
            id: m.id.to_string(),
            organization_id: m.organization_id.to_string(),
            user_id: m.user_id.to_string(),
            role: m.role.to_string(),
            user: None,
            created_at: Some(datetime_to_timestamp(m.created_at)),
            updated_at: Some(datetime_to_timestamp(m.updated_at)),
        }
    }
}

pub fn member_with_user(m: core::OrganizationMember, user: Option<core::User>) -> Member {
    Member {
        id: m.id.to_string(),
        organization_id: m.organization_id.to_string(),
        user_id: m.user_id.to_string(),
        role: m.role.to_string(),
        user: user.map(User::from),
        created_at: Some(datetime_to_timestamp(m.created_at)),
        updated_at: Some(datetime_to_timestamp(m.updated_at)),
    }
}

impl From<core::ApiKey> for ApiKey {
    fn from(k: core::ApiKey) -> Self {
        ApiKey {
            id: k.id.to_string(),
            user_id: k.user_id.to_string(),
            organization_id: k.organization_id.map(|id| id.to_string()),
            name: k.name,
            prefix: k.prefix,
            scopes: k.scopes,
            expires_at: optional_timestamp(k.expires_at),
            last_used_at: optional_timestamp(k.last_used_at),
            created_at: Some(datetime_to_timestamp(k.created_at)),
        }
    }
}

pub use api_key_service_client::ApiKeyServiceClient;
pub use api_key_service_server::{ApiKeyService, ApiKeyServiceServer};
pub use auth_service_client::AuthServiceClient;
pub use auth_service_server::{AuthService, AuthServiceServer};
pub use health_service_client::HealthServiceClient;
pub use health_service_server::{HealthService, HealthServiceServer};
pub use organization_service_client::OrganizationServiceClient;
pub use organization_service_server::{OrganizationService, OrganizationServiceServer};
pub use session_service_client::SessionServiceClient;
pub use session_service_server::{SessionService, SessionServiceServer};
pub use user_service_client::UserServiceClient;
pub use user_service_server::{UserService, UserServiceServer};
