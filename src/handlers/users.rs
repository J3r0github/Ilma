use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use utoipa::path;
use uuid::Uuid;
use log::{info, warn};
use regex::Regex;

use crate::auth::{extract_claims, hash_password};
use crate::db::DbPool;
use crate::models::{User, CreateUserRequest, PublicKeyResponse, SetRecoveryKeyRequest, RecoveryKeyResponse};
use crate::errors::ApiError;
use sentry;

#[utoipa::path(
    get,
    path = "/api/me",
    tag = "users",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Current authenticated user", body = User),
        (status = 401, description = "Unauthorized")
    )
)]
pub async fn get_me(
    req: HttpRequest,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    let user = sqlx::query_as::<_, User>(
        "SELECT id, username, email, password_hash, role, is_superuser, public_key, recovery_key, encrypted_private_key_blob, created_at, updated_at 
         FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        ApiError::from(e)
    })?;

    match user {
        Some(user) => {
            info!("User {} accessed their profile", user.id);
            Ok(HttpResponse::Ok().json(user))
        }
        None => {
            warn!("User {} not found in database", user_id);
            sentry::capture_message(
                &format!("User {} not found in database", user_id),
                sentry::Level::Warning
            );
            Ok(HttpResponse::NotFound().json(json!({"error": {"code": "USER_NOT_FOUND", "message": "User not found"}})))
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/users",
    tag = "users",
    security(("bearerAuth" = [])),
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created successfully"),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn create_user(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    user_req: web::Json<CreateUserRequest>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    // Check if user has permission to create users (superuser or principal)
    if !claims.is_superuser && !matches!(claims.role, crate::models::UserRole::Principal) {
        warn!("User {} attempted to create user without permissions", claims.sub);
        sentry::capture_message(
            &format!("User {} attempted to create user without permissions", claims.sub),
            sentry::Level::Warning
        );
        return Err(ApiError::AuthorizationError);
    }

    // Validate username format
    if user_req.username.trim().is_empty() || user_req.username.len() > 50 {
        return Err(ApiError::ValidationError("Username must be between 1 and 50 characters".to_string()));
    }
    
    // EMAIL VALIDATION. This could be better, but we want to go frontend first for this.
    // Validate email format
    if user_req.email.trim().is_empty() || user_req.email.len() > 100
        || user_req.email.contains(' ') {
        return Err(ApiError::ValidationError("Email must be a valid email address".to_string()));
    }

    // validate email format using regex
    let email_regex = Regex::new(r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$").unwrap();
    if !email_regex.is_match(&user_req.email) {
        return Err(ApiError::ValidationError("Invalid email format".to_string()));
}

    // Validate password strength
    if user_req.password.len() < 8 {
        return Err(ApiError::ValidationError("Password must be at least 8 characters long".to_string()));
    }

    let password_hash = hash_password(&user_req.password)?;
    let user_id = Uuid::new_v4();
    
    sqlx::query(
        "INSERT INTO users (id, username, email, password_hash, role, public_key) 
         VALUES ($1, $2, $3, $4, $5, $6)"
    )
    .bind(user_id)
    .bind(&user_req.username)
    .bind(&user_req.email)
    .bind(password_hash)
    .bind(&user_req.role)
    .bind(&user_req.public_key)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        ApiError::from(e)
    })?;

    info!("User {} created new user with ID: {}", claims.sub, user_id);
    Ok(HttpResponse::Created().json(json!({"message": "User created successfully", "id": user_id})))
}

#[utoipa::path(
    get,
    path = "/api/users/{id}/public_key",
    tag = "users",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, description = "User UUID")
    ),
    responses(
        (status = 200, description = "User's public key", body = PublicKeyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found")
    )
)]
pub async fn get_user_public_key(
    path: web::Path<Uuid>,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, ApiError> {
    let user_id = path.into_inner();

    let public_key: Option<String> = sqlx::query_scalar(
        "SELECT public_key FROM users WHERE id = $1"
    )
    .bind(user_id)
    .fetch_optional(pool.as_ref())
    .await?;

    match public_key {
        Some(key) => {
            info!("Public key requested for user: {}", user_id);
            Ok(HttpResponse::Ok().json(PublicKeyResponse { public_key: key }))
        }
        None => {
            warn!("Public key requested for non-existent user: {}", user_id);
            Ok(HttpResponse::NotFound().json(json!({"error": {"code": "USER_NOT_FOUND", "message": "User not found"}})))
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/user/recovery-key/{username}",
    tag = "users",
    params(
        ("username" = String, Path, description = "Username")
    ),
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "Recovery key retrieved", body = RecoveryKeyResponse),
        (status = 403, description = "Forbidden — admin access only"),
        (status = 404, description = "User not found")
    )
)]
pub async fn get_recovery_key(
    req: HttpRequest,
    path: web::Path<String>,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    // Only superusers can get recovery keys
    if !claims.is_superuser {
        warn!("User {} attempted to get recovery key without admin permissions", claims.sub);
        return Err(ApiError::AuthorizationError);
    }

    let username = path.into_inner();

    let user_data: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT recovery_key FROM users WHERE username = $1"
    )
    .bind(&username)
    .fetch_optional(pool.as_ref())
    .await?;

    match user_data {
        Some((recovery_key,)) => {
            if let Some(key) = recovery_key {
                info!("Recovery key requested for user: {}", username);
                Ok(HttpResponse::Ok().json(RecoveryKeyResponse { recovery_key: key }))
            } else {
                info!("Recovery key requested for user {} but none set", username);
                Ok(HttpResponse::NotFound().json(json!({"error": {"code": "RECOVERY_KEY_NOT_SET", "message": "Recovery key not set for this user"}})))
            }
        }
        None => {
            warn!("Recovery key requested for non-existent user: {}", username);
            Ok(HttpResponse::NotFound().json(json!({"error": {"code": "USER_NOT_FOUND", "message": "User not found"}})))
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/user/set-recovery-key",
    tag = "users",
    security(("bearerAuth" = [])),
    request_body = SetRecoveryKeyRequest,
    responses(
        (status = 200, description = "Recovery key updated"),
        (status = 400, description = "Invalid data or unauthorized")
    )
)]
pub async fn set_recovery_key(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    recovery_req: web::Json<SetRecoveryKeyRequest>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    // Check if user is admin or is setting their own recovery key
    let user_id = if claims.is_superuser {
        // Admin can set recovery key for any user
        let user_id: Option<uuid::Uuid> = sqlx::query_scalar(
            "SELECT id FROM users WHERE username = $1"
        )
        .bind(&recovery_req.username)
        .fetch_optional(pool.as_ref())
        .await?;
        
        user_id.ok_or_else(|| {
            ApiError::ValidationError("User not found".to_string())
        })?
    } else {
        // Regular user can only set their own recovery key
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| ApiError::ValidationError("Invalid user ID format".to_string()))?;

        // Verify the username matches the authenticated user
        let user_username: Option<String> = sqlx::query_scalar(
            "SELECT username FROM users WHERE id = $1"
        )
        .bind(user_id)
        .fetch_optional(pool.as_ref())
        .await?;

        match user_username {
            Some(username) if username == recovery_req.username => user_id,
            Some(_) => {
                warn!("User {} attempted to set recovery key for different user {}", claims.sub, recovery_req.username);
                return Err(ApiError::AuthorizationError);
            }
            None => {
                return Err(ApiError::AuthenticationError);
            }
        }
    };

    // Validate recovery key format
    if recovery_req.recovery_key.trim().is_empty() {
        return Err(ApiError::ValidationError("Recovery key cannot be empty".to_string()));
    }

    // Update recovery key
    sqlx::query(
        "UPDATE users SET recovery_key = $1, updated_at = NOW() WHERE id = $2"
    )
    .bind(&recovery_req.recovery_key)
    .bind(user_id)
    .execute(pool.as_ref())
    .await?;

    info!("Recovery key updated for user: {}", user_id);
    Ok(HttpResponse::Ok().json(json!({"message": "Recovery key updated"})))
}

#[utoipa::path(
    get,
    path = "/api/user/public-key/{username}",
    tag = "users",
    security(("bearerAuth" = [])),
    params(
        ("username" = String, Path, description = "Username")
    ),
    responses(
        (status = 200, description = "User's public key retrieved", body = PublicKeyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found")
    )
)]
pub async fn get_user_public_key_by_username(
    path: web::Path<String>,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, ApiError> {
    let username = path.into_inner();

    let public_key: Option<String> = sqlx::query_scalar(
        "SELECT public_key FROM users WHERE username = $1"
    )
    .bind(&username)
    .fetch_optional(pool.as_ref())
    .await?;

    match public_key {
        Some(key) => {
            info!("Public key requested for user: {}", username);
            Ok(HttpResponse::Ok().json(PublicKeyResponse { public_key: key }))
        }
        None => {
            warn!("Public key requested for non-existent user: {}", username);
            Ok(HttpResponse::NotFound().json(json!({"error": {"code": "USER_NOT_FOUND", "message": "User not found"}})))
        }
    }
}
