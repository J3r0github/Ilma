use actix_web::{HttpResponse, ResponseError};
use serde_json::json;
use std::fmt;

#[derive(Debug)]
pub enum ApiError {
    DatabaseError,
    AuthenticationError,
    AuthorizationError,
    ValidationError(String),
    NotFound,
    InternalServerError,
    BadRequest(String),
}

impl fmt::Display for ApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ApiError::DatabaseError => write!(f, "Database operation failed"),
            ApiError::AuthenticationError => write!(f, "Authentication required"),
            ApiError::AuthorizationError => write!(f, "Insufficient permissions"),
            ApiError::ValidationError(msg) => write!(f, "Validation error: {}", msg),
            ApiError::NotFound => write!(f, "Resource not found"),
            ApiError::InternalServerError => write!(f, "Internal server error"),
            ApiError::BadRequest(msg) => write!(f, "Bad request: {}", msg),
        }
    }
}

impl ResponseError for ApiError {
    fn error_response(&self) -> HttpResponse {
        let (status, code, message) = match self {
            ApiError::DatabaseError => (
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "DATABASE_ERROR",
                "Database operation failed"
            ),
            ApiError::AuthenticationError => (
                actix_web::http::StatusCode::UNAUTHORIZED,
                "AUTHENTICATION_REQUIRED",
                "Authentication required"
            ),
            ApiError::AuthorizationError => (
                actix_web::http::StatusCode::FORBIDDEN,
                "INSUFFICIENT_PERMISSIONS",
                "Insufficient permissions"
            ),
            ApiError::ValidationError(msg) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                "VALIDATION_ERROR",
                msg.as_str()
            ),
            ApiError::NotFound => (
                actix_web::http::StatusCode::NOT_FOUND,
                "NOT_FOUND",
                "Resource not found"
            ),
            ApiError::InternalServerError => (
                actix_web::http::StatusCode::INTERNAL_SERVER_ERROR,
                "INTERNAL_ERROR",
                "Internal server error"
            ),
            ApiError::BadRequest(msg) => (
                actix_web::http::StatusCode::BAD_REQUEST,
                "BAD_REQUEST",
                msg.as_str()
            ),
        };

        HttpResponse::build(status).json(json!({
            "error": {
                "code": code,
                "message": message
            }
        }))
    }
}

// Convenience type alias
pub type ApiResult<T> = Result<T, ApiError>;

// Helper functions for common error conversions
impl From<sqlx::Error> for ApiError {
    fn from(err: sqlx::Error) -> Self {
        // Log the actual error internally without exposing it
        log::error!("Database error: {:?}", err);
        ApiError::DatabaseError
    }
}

impl From<argon2::password_hash::Error> for ApiError {
    fn from(err: argon2::password_hash::Error) -> Self {
        log::error!("Password hashing error: {:?}", err);
        ApiError::InternalServerError
    }
}

impl From<jsonwebtoken::errors::Error> for ApiError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        log::error!("JWT error: {:?}", err);
        match err.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => ApiError::AuthenticationError,
            jsonwebtoken::errors::ErrorKind::InvalidToken => ApiError::AuthenticationError,
            _ => ApiError::InternalServerError,
        }
    }
}
