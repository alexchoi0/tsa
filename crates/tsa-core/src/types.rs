use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    pub phone: Option<String>,
    pub phone_verified: bool,
    pub name: Option<String>,
    pub image: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub id: Uuid,
    pub user_id: Uuid,
    pub provider: String,
    pub provider_account_id: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: String,
    pub token_type: TokenType,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum TokenType {
    EmailVerification,
    PasswordReset,
    MagicLink,
    EmailOtp,
    PhoneOtp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TwoFactor {
    pub id: Uuid,
    pub user_id: Uuid,
    pub secret: String,
    pub backup_codes: Vec<String>,
    pub enabled: bool,
    pub verified: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Organization {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
    pub logo: Option<String>,
    pub metadata: Option<serde_json::Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum OrganizationRole {
    Owner,
    Admin,
    Member,
}

impl std::fmt::Display for OrganizationRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OrganizationRole::Owner => write!(f, "owner"),
            OrganizationRole::Admin => write!(f, "admin"),
            OrganizationRole::Member => write!(f, "member"),
        }
    }
}

impl std::str::FromStr for OrganizationRole {
    type Err = crate::TsaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "owner" => Ok(OrganizationRole::Owner),
            "admin" => Ok(OrganizationRole::Admin),
            "member" => Ok(OrganizationRole::Member),
            _ => Err(crate::TsaError::InvalidInput(format!("Invalid role: {}", s))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationMember {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub user_id: Uuid,
    pub role: OrganizationRole,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum InvitationStatus {
    Pending,
    Accepted,
    Expired,
    Revoked,
}

impl std::fmt::Display for InvitationStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InvitationStatus::Pending => write!(f, "pending"),
            InvitationStatus::Accepted => write!(f, "accepted"),
            InvitationStatus::Expired => write!(f, "expired"),
            InvitationStatus::Revoked => write!(f, "revoked"),
        }
    }
}

impl std::str::FromStr for InvitationStatus {
    type Err = crate::TsaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(InvitationStatus::Pending),
            "accepted" => Ok(InvitationStatus::Accepted),
            "expired" => Ok(InvitationStatus::Expired),
            "revoked" => Ok(InvitationStatus::Revoked),
            _ => Err(crate::TsaError::InvalidInput(format!("Invalid status: {}", s))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrganizationInvitation {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub email: String,
    pub role: OrganizationRole,
    pub token_hash: String,
    pub invited_by: Uuid,
    pub status: InvitationStatus,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiKey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub organization_id: Option<Uuid>,
    pub name: String,
    pub key_hash: String,
    pub prefix: String,
    pub scopes: Vec<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Passkey {
    pub id: Uuid,
    pub user_id: Uuid,
    pub credential_id: Vec<u8>,
    pub public_key: Vec<u8>,
    pub counter: u32,
    pub name: String,
    pub transports: Option<Vec<String>>,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyChallenge {
    pub id: Uuid,
    pub user_id: Option<Uuid>,
    pub challenge: Vec<u8>,
    pub challenge_type: PasskeyChallengeType,
    pub state: Vec<u8>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PasskeyChallengeType {
    Registration,
    Authentication,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
    Cancelled,
}

impl std::fmt::Display for ApprovalStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApprovalStatus::Pending => write!(f, "pending"),
            ApprovalStatus::Approved => write!(f, "approved"),
            ApprovalStatus::Denied => write!(f, "denied"),
            ApprovalStatus::Expired => write!(f, "expired"),
            ApprovalStatus::Cancelled => write!(f, "cancelled"),
        }
    }
}

impl std::str::FromStr for ApprovalStatus {
    type Err = crate::TsaError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "pending" => Ok(ApprovalStatus::Pending),
            "approved" => Ok(ApprovalStatus::Approved),
            "denied" => Ok(ApprovalStatus::Denied),
            "expired" => Ok(ApprovalStatus::Expired),
            "cancelled" => Ok(ApprovalStatus::Cancelled),
            _ => Err(crate::TsaError::InvalidInput(format!("Invalid approval status: {}", s))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRequest {
    pub id: Uuid,
    pub organization_id: Uuid,
    pub requester_id: Uuid,
    pub policy_name: String,
    pub permission: String,
    pub resource_type: Option<String>,
    pub resource_id: Option<String>,
    pub reason: Option<String>,
    pub context: Option<serde_json::Value>,
    pub status: ApprovalStatus,
    pub required_approvals: u32,
    pub expires_at: DateTime<Utc>,
    pub auto_deny_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub resolved_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ApprovalDecision {
    Approved,
    Denied,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalResponse {
    pub id: Uuid,
    pub request_id: Uuid,
    pub approver_id: Uuid,
    pub decision: ApprovalDecision,
    pub comment: Option<String>,
    pub channel: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalToken {
    pub id: Uuid,
    pub request_id: Uuid,
    pub token_hash: String,
    pub approver_email: Option<String>,
    pub channel: String,
    pub decision: Option<ApprovalDecision>,
    pub expires_at: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
    pub used_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_organization_role_display() {
        assert_eq!(OrganizationRole::Owner.to_string(), "owner");
        assert_eq!(OrganizationRole::Admin.to_string(), "admin");
        assert_eq!(OrganizationRole::Member.to_string(), "member");
    }

    #[test]
    fn test_organization_role_from_str() {
        assert_eq!("owner".parse::<OrganizationRole>().unwrap(), OrganizationRole::Owner);
        assert_eq!("ADMIN".parse::<OrganizationRole>().unwrap(), OrganizationRole::Admin);
        assert_eq!("Member".parse::<OrganizationRole>().unwrap(), OrganizationRole::Member);
        assert!("invalid".parse::<OrganizationRole>().is_err());
    }

    #[test]
    fn test_invitation_status_display() {
        assert_eq!(InvitationStatus::Pending.to_string(), "pending");
        assert_eq!(InvitationStatus::Accepted.to_string(), "accepted");
        assert_eq!(InvitationStatus::Expired.to_string(), "expired");
        assert_eq!(InvitationStatus::Revoked.to_string(), "revoked");
    }

    #[test]
    fn test_invitation_status_from_str() {
        assert_eq!("pending".parse::<InvitationStatus>().unwrap(), InvitationStatus::Pending);
        assert_eq!("ACCEPTED".parse::<InvitationStatus>().unwrap(), InvitationStatus::Accepted);
        assert!("invalid".parse::<InvitationStatus>().is_err());
    }

    #[test]
    fn test_approval_status_display() {
        assert_eq!(ApprovalStatus::Pending.to_string(), "pending");
        assert_eq!(ApprovalStatus::Approved.to_string(), "approved");
        assert_eq!(ApprovalStatus::Denied.to_string(), "denied");
    }

    #[test]
    fn test_approval_status_from_str() {
        assert_eq!("pending".parse::<ApprovalStatus>().unwrap(), ApprovalStatus::Pending);
        assert_eq!("APPROVED".parse::<ApprovalStatus>().unwrap(), ApprovalStatus::Approved);
        assert!("unknown".parse::<ApprovalStatus>().is_err());
    }

    #[test]
    fn test_user_serialization() {
        let user = User {
            id: Uuid::new_v4(),
            email: "test@example.com".to_string(),
            email_verified: true,
            phone: Some("+1234567890".to_string()),
            phone_verified: false,
            name: Some("Test User".to_string()),
            image: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };

        let json = serde_json::to_string(&user).unwrap();
        let deserialized: User = serde_json::from_str(&json).unwrap();

        assert_eq!(user.id, deserialized.id);
        assert_eq!(user.email, deserialized.email);
        assert_eq!(user.phone, deserialized.phone);
    }

    #[test]
    fn test_session_serialization() {
        let session = Session {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            token_hash: "hash123".to_string(),
            expires_at: Utc::now() + chrono::Duration::days(1),
            created_at: Utc::now(),
            ip_address: Some("127.0.0.1".to_string()),
            user_agent: Some("Mozilla/5.0".to_string()),
        };

        let json = serde_json::to_string(&session).unwrap();
        let deserialized: Session = serde_json::from_str(&json).unwrap();

        assert_eq!(session.id, deserialized.id);
        assert_eq!(session.user_id, deserialized.user_id);
    }

    #[test]
    fn test_token_type_equality() {
        assert_eq!(TokenType::EmailVerification, TokenType::EmailVerification);
        assert_ne!(TokenType::EmailVerification, TokenType::PasswordReset);
        assert_ne!(TokenType::MagicLink, TokenType::EmailOtp);
    }

    #[test]
    fn test_api_key_serialization() {
        let api_key = ApiKey {
            id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            organization_id: Some(Uuid::new_v4()),
            name: "Test Key".to_string(),
            key_hash: "hash".to_string(),
            prefix: "tsa_abc".to_string(),
            scopes: vec!["read:users".to_string(), "write:users".to_string()],
            expires_at: None,
            last_used_at: None,
            created_at: Utc::now(),
        };

        let json = serde_json::to_string(&api_key).unwrap();
        let deserialized: ApiKey = serde_json::from_str(&json).unwrap();

        assert_eq!(api_key.scopes, deserialized.scopes);
        assert_eq!(api_key.prefix, deserialized.prefix);
    }
}
