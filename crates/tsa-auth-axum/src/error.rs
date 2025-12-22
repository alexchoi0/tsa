use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use tsa_auth_core::TsaError;

#[derive(Debug)]
pub struct ApiError {
    pub status: StatusCode,
    pub code: String,
    pub message: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: ErrorBody,
}

#[derive(Serialize)]
struct ErrorBody {
    code: String,
    message: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let body = ErrorResponse {
            error: ErrorBody {
                code: self.code,
                message: self.message,
            },
        };

        (self.status, Json(body)).into_response()
    }
}

impl From<TsaError> for ApiError {
    fn from(err: TsaError) -> Self {
        match err {
            TsaError::UserAlreadyExists => Self {
                status: StatusCode::CONFLICT,
                code: "USER_EXISTS".to_string(),
                message: "A user with this email already exists".to_string(),
            },
            TsaError::UserNotFound => Self {
                status: StatusCode::NOT_FOUND,
                code: "USER_NOT_FOUND".to_string(),
                message: "User not found".to_string(),
            },
            TsaError::InvalidCredentials => Self {
                status: StatusCode::UNAUTHORIZED,
                code: "INVALID_CREDENTIALS".to_string(),
                message: "Invalid email or password".to_string(),
            },
            TsaError::SessionNotFound => Self {
                status: StatusCode::UNAUTHORIZED,
                code: "SESSION_NOT_FOUND".to_string(),
                message: "Session not found or expired".to_string(),
            },
            TsaError::SessionExpired => Self {
                status: StatusCode::UNAUTHORIZED,
                code: "SESSION_EXPIRED".to_string(),
                message: "Session has expired".to_string(),
            },
            TsaError::EmailNotVerified => Self {
                status: StatusCode::FORBIDDEN,
                code: "EMAIL_NOT_VERIFIED".to_string(),
                message: "Email address has not been verified".to_string(),
            },
            TsaError::InvalidToken => Self {
                status: StatusCode::UNAUTHORIZED,
                code: "INVALID_TOKEN".to_string(),
                message: "Invalid or expired token".to_string(),
            },
            TsaError::TokenExpired => Self {
                status: StatusCode::UNAUTHORIZED,
                code: "TOKEN_EXPIRED".to_string(),
                message: "Token has expired".to_string(),
            },
            TsaError::OrganizationNotFound => Self {
                status: StatusCode::NOT_FOUND,
                code: "ORG_NOT_FOUND".to_string(),
                message: "Organization not found".to_string(),
            },
            TsaError::OrganizationAlreadyExists => Self {
                status: StatusCode::CONFLICT,
                code: "ORG_EXISTS".to_string(),
                message: "An organization with this slug already exists".to_string(),
            },
            TsaError::InsufficientPermissions => Self {
                status: StatusCode::FORBIDDEN,
                code: "FORBIDDEN".to_string(),
                message: "Insufficient permissions".to_string(),
            },
            TsaError::InvalidApiKey => Self {
                status: StatusCode::UNAUTHORIZED,
                code: "INVALID_API_KEY".to_string(),
                message: "Invalid API key".to_string(),
            },
            TsaError::TwoFactorNotEnabled => Self {
                status: StatusCode::BAD_REQUEST,
                code: "2FA_NOT_ENABLED".to_string(),
                message: "Two-factor authentication is not enabled".to_string(),
            },
            TsaError::TwoFactorAlreadyEnabled => Self {
                status: StatusCode::CONFLICT,
                code: "2FA_ALREADY_ENABLED".to_string(),
                message: "Two-factor authentication is already enabled".to_string(),
            },
            TsaError::InvalidTwoFactorCode => Self {
                status: StatusCode::UNAUTHORIZED,
                code: "2FA_INVALID".to_string(),
                message: "Invalid two-factor code".to_string(),
            },
            _ => Self {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                code: "INTERNAL_ERROR".to_string(),
                message: "An internal error occurred".to_string(),
            },
        }
    }
}

impl ApiError {
    pub fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            code: "BAD_REQUEST".to_string(),
            message: message.into(),
        }
    }

    pub fn unauthorized(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            code: "UNAUTHORIZED".to_string(),
            message: message.into(),
        }
    }
}
