use actix_web::{web, HttpResponse, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use chrono::{Duration, Utc};
use jsonwebtoken::{encode, decode, Header, Validation, EncodingKey, DecodingKey};
use rand::rngs::OsRng;
use serde_json::json;
use std::env;
use log::{error, warn, info};

use crate::models::{Claims, LoginRequest, LoginResponse, User, UserRole, PasswordResetRequest, ResetPasswordRequest, PasswordResetToken};
use crate::db::DbPool;
use crate::errors::{ApiError, ApiResult};
use rand::Rng;

pub fn hash_password(password: &str) -> ApiResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> ApiResult<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| {
            error!("Failed to parse password hash: {:?}", e);
            ApiError::InternalServerError
        })?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}

fn validate_jwt_secret(secret: &str) -> ApiResult<()> {
    if secret.len() < 32 {
        error!("JWT secret too short. Must be at least 32 characters");
        return Err(ApiError::InternalServerError);
    }
    
    if secret.contains("change-this") || secret.contains("secret") {
        error!("JWT secret appears to be a default/weak value");
        return Err(ApiError::InternalServerError);
    }
    
    Ok(())
}

pub fn create_jwt(user: &User) -> ApiResult<String> {
    let secret = env::var("JWT_SECRET")
        .map_err(|_| {
            error!("JWT_SECRET environment variable not set");
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
    info!("Login attempt for email: {}", login_req.email);
    
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
        // Don't expose database errors to users - return authentication error instead
        ApiError::AuthenticationError
    })?;

    match user {
        Some(user) => {
            if verify_password(&login_req.password, &user.password_hash)? {
                let token = create_jwt(&user)?;
                info!("Successful login for user: {}", user.id);
                Ok(HttpResponse::Ok().json(LoginResponse { token }))
            } else {
                warn!("Failed login attempt for email: {}", login_req.email);
                Ok(HttpResponse::Unauthorized().json(json!({"error": "Invalid credentials"})))
            }
        }
        None => {
            warn!("Login attempt for non-existent email: {}", login_req.email);
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

// Testing mode functions
pub fn is_testing_mode() -> bool {
    env::var("TESTING_MODE")
        .map(|v| v.to_lowercase() == "true" || v == "1")
        .unwrap_or(false)
}

use uuid::Uuid;
use std::collections::HashSet;
use std::sync::{Mutex, LazyLock};

// Track test user IDs for cleanup
static TEST_USER_IDS: LazyLock<Mutex<HashSet<Uuid>>> = LazyLock::new(|| Mutex::new(HashSet::new()));

pub async fn create_test_users(pool: &DbPool) -> ApiResult<()> {
    if !is_testing_mode() {
        return Ok(());
    }

    info!("Creating test users for testing mode...");
    
    let mut test_users = Vec::new();
    
    // Add main test user from environment variables
    if let (Ok(username), Ok(email), Ok(password)) = (
        env::var("TEST_USERNAME"),
        env::var("TEST_EMAIL"),
        env::var("TEST_PASSWORD")
    ) {
        test_users.push((username, email, password, UserRole::Principal, true));
    }
    
    // Add additional test users (TEST_USER_1 through TEST_USER_5)
    for i in 1..=5 {
        if let (Ok(username), Ok(email), Ok(password)) = (
            env::var(&format!("TEST_USER_{}_USERNAME", i)),
            env::var(&format!("TEST_USER_{}_EMAIL", i)),
            env::var(&format!("TEST_USER_{}_PASSWORD", i))
        ) {
            // Parse role from environment variable, default to Student
            let role = env::var(&format!("TEST_USER_{}_ROLE", i))
                .unwrap_or_else(|_| "student".to_string())
                .to_lowercase();
            
            let (user_role, is_superuser) = match role.as_str() {
                "admin" | "principal" => (UserRole::Principal, true),
                "teacher" => (UserRole::Teacher, false),
                "student" | _ => (UserRole::Student, false),
            };
            
            test_users.push((username, email, password, user_role, is_superuser));
        }
    }
    
    if test_users.is_empty() {
        warn!("No test users configured in environment variables");
        return Ok(());
    }

    let mut test_user_ids = TEST_USER_IDS.lock().unwrap();
    
    for (username, email, password, role, is_superuser) in test_users {
        let user_id = Uuid::new_v4();
        let password_hash = hash_password(&password)?;
        
        // Generate a dummy public key for testing
        let public_key = format!("TEST_PUBLIC_KEY_{}", user_id);
        
        // Create the test user with proper error handling for schema differences
        let result = sqlx::query(
            r#"
            INSERT INTO users (id, username, email, password_hash, role, is_superuser, public_key, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
            ON CONFLICT (email) DO UPDATE SET
                username = EXCLUDED.username,
                password_hash = EXCLUDED.password_hash,
                role = EXCLUDED.role,
                is_superuser = EXCLUDED.is_superuser,
                public_key = EXCLUDED.public_key,
                updated_at = NOW()
            "#
        )
        .bind(user_id)
        .bind(&username)
        .bind(&email)
        .bind(&password_hash)
        .bind(&role)
        .bind(is_superuser)
        .bind(&public_key)
        .execute(pool)
        .await;

        match result {
            Ok(_) => {
                test_user_ids.insert(user_id);
                info!("Created test user: {} ({})", username, email);
            }
            Err(e) => {
                // If username column doesn't exist, try without it
                if e.to_string().contains("username") {
                    warn!("Username column not found, creating test user without username");
                    sqlx::query(
                        r#"
                        INSERT INTO users (id, email, password_hash, role, is_superuser, public_key, created_at, updated_at)
                        VALUES ($1, $2, $3, $4, $5, $6, NOW(), NOW())
                        ON CONFLICT (email) DO UPDATE SET
                            password_hash = EXCLUDED.password_hash,
                            role = EXCLUDED.role,
                            is_superuser = EXCLUDED.is_superuser,
                            public_key = EXCLUDED.public_key,
                            updated_at = NOW()
                        "#
                    )
                    .bind(user_id)
                    .bind(&email)
                    .bind(&password_hash)
                    .bind(&role)
                    .bind(is_superuser)
                    .bind(&public_key)
                    .execute(pool)
                    .await
                    .map_err(|e| {
                        error!("Failed to create test user {} (fallback): {:?}", username, e);
                        ApiError::InternalServerError
                    })?;
                    
                    test_user_ids.insert(user_id);
                    info!("Created test user: {} ({})", username, email);
                } else {
                    error!("Failed to create test user {}: {:?}", username, e);
                    return Err(ApiError::InternalServerError);
                }
            }
        }
    }

    Ok(())
}

pub async fn cleanup_test_users(pool: &DbPool) -> ApiResult<()> {
    if !is_testing_mode() {
        return Ok(());
    }

    info!("Cleaning up test users and their data...");
    
    // Get test user IDs and immediately drop the guard
    let ids: Vec<Uuid> = {
        let test_user_ids = TEST_USER_IDS.lock().unwrap();
        
        if test_user_ids.is_empty() {
            info!("No test users to clean up");
            return Ok(());
        }
        
        // Convert to Vec for use in SQL query
        test_user_ids.iter().cloned().collect()
    }; // Guard is dropped here
    
    // Clean up in reverse order of foreign key dependencies
    
    // 1. Delete message encrypted keys
    sqlx::query("DELETE FROM message_encrypted_keys WHERE message_id IN (SELECT id FROM messages WHERE sender_id = ANY($1))")
        .bind(&ids)
        .execute(pool)
        .await?;
    
    // 2. Delete messages
    sqlx::query("DELETE FROM messages WHERE sender_id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await?;
    
    // 3. Delete thread participants
    sqlx::query("DELETE FROM thread_participants WHERE user_id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await?;
    
    // 4. Delete threads created by test users
    sqlx::query("DELETE FROM threads WHERE id IN (SELECT DISTINCT thread_id FROM thread_participants WHERE user_id = ANY($1))")
        .bind(&ids)
        .execute(pool)
        .await?;
    
    // 5. Delete attendance records
    sqlx::query("DELETE FROM attendance WHERE student_id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await?;
    
    // 6. Delete grades
    sqlx::query("DELETE FROM grades WHERE student_id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await?;
    
    // 7. Delete class enrollments
    sqlx::query("DELETE FROM class_students WHERE student_id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await?;
    
    // 8. Delete classes taught by test users
    sqlx::query("DELETE FROM classes WHERE teacher_id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await?;
    
    // 9. Delete user permission assignments
    sqlx::query("DELETE FROM user_permissions WHERE user_id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await?;
    
    // 10. Delete password reset tokens
    sqlx::query("DELETE FROM password_reset_tokens WHERE user_id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await?;
    
    // 11. Finally, delete the test users themselves
    sqlx::query("DELETE FROM users WHERE id = ANY($1)")
        .bind(&ids)
        .execute(pool)
        .await?;

    info!("Successfully cleaned up {} test users and their data", ids.len());
    Ok(())
}
