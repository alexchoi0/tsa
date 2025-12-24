use tonic::Status;
use tsa_auth_core::TsaError;

pub fn to_status(err: TsaError) -> Status {
    match err {
        TsaError::UserAlreadyExists => {
            Status::already_exists("A user with this email already exists")
        }
        TsaError::UserNotFound => Status::not_found("User not found"),
        TsaError::InvalidCredentials => Status::unauthenticated("Invalid email or password"),
        TsaError::SessionNotFound => Status::unauthenticated("Session not found or expired"),
        TsaError::SessionExpired => Status::unauthenticated("Session has expired"),
        TsaError::EmailNotVerified => {
            Status::permission_denied("Email address has not been verified")
        }
        TsaError::InvalidToken => Status::unauthenticated("Invalid or expired token"),
        TsaError::TokenExpired => Status::unauthenticated("Token has expired"),
        TsaError::OrganizationNotFound => Status::not_found("Organization not found"),
        TsaError::OrganizationAlreadyExists => {
            Status::already_exists("An organization with this slug already exists")
        }
        TsaError::InsufficientPermissions => Status::permission_denied("Insufficient permissions"),
        TsaError::InvalidApiKey => Status::unauthenticated("Invalid API key"),
        TsaError::TwoFactorNotEnabled => {
            Status::failed_precondition("Two-factor authentication is not enabled")
        }
        TsaError::TwoFactorAlreadyEnabled => {
            Status::already_exists("Two-factor authentication is already enabled")
        }
        TsaError::InvalidTwoFactorCode => Status::unauthenticated("Invalid two-factor code"),
        TsaError::InvalidInput(msg) => Status::invalid_argument(msg),
        TsaError::AccountLocked => Status::permission_denied("Account is locked"),
        TsaError::PasswordPolicyViolation(msg) => {
            Status::invalid_argument(format!("Password policy violation: {}", msg))
        }
        TsaError::PasswordRecentlyUsed => {
            Status::invalid_argument("Password has been used recently")
        }
        TsaError::IpBlocked => Status::permission_denied("IP address is blocked"),
        _ => Status::internal("An internal error occurred"),
    }
}
