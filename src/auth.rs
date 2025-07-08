use actix_web::{web, HttpResponse, Result};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use serde_json::json;
use std::env;
use log::{error, warn, info, debug};
use sentry;
use rand::Rng;

use crate::models::{Claims, LoginRequest, LoginResponse, User, PasswordResetRequest, ResetPasswordRequest, PasswordResetToken};
use crate::db::DbPool;
use crate::errors::{ApiError, ApiResult};
use crate::utils::verify_password;
use crate::configloader::{create_test_data_from_config, cleanup_test_data};

fn validate_jwt_secret(secret: &str) -> ApiResult<()> {
    if secret.len() < 32 {
        error!("JWT secret too short. Must be at least 32 characters");
        sentry::capture_message("JWT secret too short", sentry::Level::Error);
        return Err(ApiError::InternalServerError);
    }
    
    if secret.contains("change-this") || secret.contains("secret") {
        error!("JWT secret appears to be a default/weak value");
        sentry::capture_message("JWT secret appears to be a default/weak value", sentry::Level::Error);
        return Err(ApiError::InternalServerError);
    }
    
    Ok(())
}

pub fn create_jwt(user: &User) -> ApiResult<String> {
    let secret = env::var("JWT_SECRET")
        .map_err(|_| {
            error!("JWT_SECRET environment variable not set");
            sentry::capture_message("JWT_SECRET environment variable not set", sentry::Level::Error);
            ApiError::InternalServerError
        })?;
    
    validate_jwt_secret(&secret)?;
    
    let expiration = Utc::now()
        .checked_add_signed(Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user.id.to_string(),
        email: user.email.clone(),
        role: user.role.clone(),
        is_superuser: user.is_superuser,
        exp: expiration,
        is_testing: None, // Regular users don't have testing mode
    };

    let token = encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )?;
    
    Ok(token)
}

pub fn verify_jwt(token: &str) -> ApiResult<Claims> {
    let secret = env::var("JWT_SECRET")
        .map_err(|_| {
            error!("JWT_SECRET environment variable not set");
            sentry::capture_message("JWT_SECRET environment variable not set", sentry::Level::Error);
            ApiError::InternalServerError
        })?;
    
    validate_jwt_secret(&secret)?;
    
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )?;
    
    Ok(token_data.claims)
}

#[utoipa::path(
    post,
    path = "/api/auth/login",
    tag = "auth",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "JWT token issued", body = LoginResponse),
        (status = 401, description = "Unauthorized - invalid credentials")
    )
)]
pub async fn login(
    pool: web::Data<DbPool>,
    login_req: web::Json<LoginRequest>,
) -> Result<HttpResponse, ApiError> {
    debug!("Login attempt for email: {}", login_req.email);
    
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, role, is_superuser, public_key, 
         COALESCE(recovery_key, '') as recovery_key, 
         COALESCE(encrypted_private_key_blob, '') as encrypted_private_key_blob, 
         created_at, updated_at 
         FROM users WHERE email = $1"
    )
    .bind(&login_req.email)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error during login: {:?}", e);
        sentry::capture_error(&e);
        // Don't expose database errors to users - return authentication error instead
        ApiError::AuthenticationError
    })?;

    match user {
        Some(user) => {
            if verify_password(&login_req.password, &user.password_hash)? {
                let token = create_jwt(&user)?;
                Ok(HttpResponse::Ok().json(LoginResponse { token }))
            } else {
                Ok(HttpResponse::Unauthorized().json(json!({"error": "Invalid credentials"})))
            }
        }
        None => {
            Ok(HttpResponse::Unauthorized().json(json!({"error": "Invalid credentials"})))
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/auth/request-password-reset",
    tag = "auth",
    request_body = PasswordResetRequest,
    responses(
        (status = 200, description = "Password reset requested"),
        (status = 400, description = "Invalid request")
    )
)]
pub async fn request_password_reset(
    pool: web::Data<DbPool>,
    reset_req: web::Json<PasswordResetRequest>,
) -> Result<HttpResponse, ApiError> {
    info!("Password reset requested for email: {}", reset_req.email);

    // Check if user exists
    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, role, is_superuser, public_key, recovery_key, encrypted_private_key_blob, created_at, updated_at 
         FROM users WHERE email = $1"
    )
    .bind(&reset_req.email)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error during password reset request: {:?}", e);
        // Don't expose database errors to users - but still return success to prevent enumeration
        ApiError::InternalServerError
    })?;

    if let Some(user) = user {
        // Generate reset token
        let reset_token: String = rand::thread_rng()
            .sample_iter(&rand::distributions::Alphanumeric)
            .take(64)
            .map(char::from)
            .collect();

        // Set expiration to 1 hour from now
        let expires_at = Utc::now() + Duration::hours(1);

        // Store reset token
        let result = sqlx::query(
            "INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES ($1, $2, $3)"
        )
        .bind(user.id)
        .bind(&reset_token)
        .bind(expires_at)
        .execute(pool.as_ref())
        .await;

        if let Err(e) = result {
            error!("Database error when storing reset token: {:?}", e);
            // Continue execution to prevent timing attacks
        } else {
            info!("Password reset token generated for user: {}", user.id);
        }
        
        // In a real application, you would send an email with the reset token
        // For now, we'll just log it (remove in production)
        // log::debug!("Reset token for {}: {}", user.email, reset_token);
        // Actually removed no because security audit report says so. Eh.
    } else {
        // Don't reveal if email exists or not
        info!("Password reset requested for non-existent email: {}", reset_req.email);
    }

    // Always return success to prevent email enumeration
    Ok(HttpResponse::Ok().json(json!({"message": "Password reset requested"})))
}

#[utoipa::path(
    post,
    path = "/api/auth/reset-password",
    tag = "auth",
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password reset successful"),
        (status = 400, description = "Invalid token or data")
    )
)]
pub async fn reset_password(
    pool: web::Data<DbPool>,
    reset_req: web::Json<ResetPasswordRequest>,
) -> Result<HttpResponse, ApiError> {
    info!("Password reset attempt with token");

    // Find valid, unused token
    let token = sqlx::query_as::<_, PasswordResetToken>(
        "SELECT id, user_id, token, expires_at, created_at, used 
         FROM password_reset_tokens 
         WHERE token = $1 AND used = FALSE AND expires_at > NOW()"
    )
    .bind(&reset_req.reset_token)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error during password reset: {:?}", e);
        ApiError::InternalServerError
    })?;

    let token = token.ok_or_else(|| {
        warn!("Invalid or expired reset token used");
        ApiError::BadRequest("Invalid or expired reset token".to_string())
    })?;

    // Update user's password and encrypted private key
    sqlx::query(
        "UPDATE users SET password_hash = $1, encrypted_private_key_blob = $2, updated_at = NOW() WHERE id = $3"
    )
    .bind(&reset_req.new_password_hash)
    .bind(&reset_req.encrypted_private_key_blob)
    .bind(token.user_id)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error updating user password: {:?}", e);
        ApiError::InternalServerError
    })?;

    // Mark token as used
    sqlx::query(
        "UPDATE password_reset_tokens SET used = TRUE WHERE id = $1"
    )
    .bind(token.id)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error marking token as used: {:?}", e);
        ApiError::InternalServerError
    })?;

    info!("Password reset successful for user: {}", token.user_id);
    Ok(HttpResponse::Ok().json(json!({"message": "Password reset successful"})))
}

// Middleware for JWT authentication
use actix_web::{dev::ServiceRequest, Error, HttpMessage};
use actix_web_httpauth::extractors::bearer::BearerAuth;

pub async fn jwt_validator(
    req: ServiceRequest,
    credentials: BearerAuth,
) -> Result<ServiceRequest, (Error, ServiceRequest)> {
    match verify_jwt(credentials.token()) {
        Ok(claims) => {
            req.extensions_mut().insert(claims);
            Ok(req)
        }
        Err(_) => {
            warn!("Invalid JWT token provided");
            Err((actix_web::error::ErrorUnauthorized("Invalid token"), req))
        }
    }
}

// Helper function to extract claims from request
pub fn extract_claims(req: &actix_web::HttpRequest) -> Option<Claims> {
    req.extensions().get::<Claims>().cloned()
}

// Legacy function for backward compatibility
pub async fn create_test_users(pool: &DbPool) -> ApiResult<()> {
    create_test_data_from_config(pool).await
}

// Legacy function for backward compatibility
pub async fn cleanup_test_users(pool: &DbPool) -> ApiResult<()> {
    cleanup_test_data(pool).await
}
