use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use uuid::Uuid;
use log::{debug, warn};
use regex::Regex;

use crate::auth::extract_claims;
use crate::utils::hash_password;
use crate::db::DbPool;
use crate::models::{User, CreateUserRequest, PublicKeyResponse, SetRecoveryKeyRequest, RecoveryKeyResponse, UserRole, UpdateUserRequest, UserSearchParams};
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
        "SELECT id, email, password_hash, role, is_superuser, public_key, recovery_key, 
         encrypted_private_key_blob, first_names, chosen_name, last_name, name_short, 
         birthday, ssn, learner_number, person_oid, avatar_url, phone, address, 
         enrollment_date, graduation_date, created_at, updated_at 
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
            debug!("User {} accessed their profile", user.id);
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
        "INSERT INTO users (id, email, password_hash, role, public_key, first_names, chosen_name, 
         last_name, name_short, birthday, ssn, learner_number, person_oid, avatar_url, phone, 
         address, enrollment_date, graduation_date) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)"
    )
    .bind(user_id)
    .bind(&user_req.email)
    .bind(password_hash)
    .bind(&user_req.role)
    .bind(&user_req.public_key)
    .bind(&user_req.first_names)
    .bind(&user_req.chosen_name)
    .bind(&user_req.last_name)
    .bind(&user_req.name_short)
    .bind(&user_req.birthday)
    .bind(&user_req.ssn)
    .bind(&user_req.learner_number)
    .bind(&user_req.person_oid)
    .bind(&user_req.avatar_url)
    .bind(&user_req.phone)
    .bind(&user_req.address)
    .bind(&user_req.enrollment_date)
    .bind(&user_req.graduation_date)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        ApiError::from(e)
    })?;

    debug!("User {} created new user with ID: {}", claims.sub, user_id);
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
            debug!("Public key requested for user: {}", user_id);
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
    path = "/api/user/recovery-key/{email}",
    tag = "users",
    params(
        ("email" = String, Path, description = "User email")
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

    let email = path.into_inner();

    let user_data: Option<(Option<String>,)> = sqlx::query_as(
        "SELECT recovery_key FROM users WHERE email = $1"
    )
    .bind(&email)
    .fetch_optional(pool.as_ref())
    .await?;

    match user_data {
        Some((recovery_key,)) => {
            if let Some(key) = recovery_key {
                debug!("Recovery key requested for user: {}", email);
                Ok(HttpResponse::Ok().json(RecoveryKeyResponse { recovery_key: key }))
            } else {
                debug!("Recovery key requested for user {} but none set", email);
                Ok(HttpResponse::NotFound().json(json!({"error": {"code": "RECOVERY_KEY_NOT_SET", "message": "Recovery key not set for this user"}})))
            }
        }
        None => {
            warn!("Recovery key requested for non-existent user: {}", email);
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
            "SELECT id FROM users WHERE email = $1"
        )
        .bind(&recovery_req.email)
        .fetch_optional(pool.as_ref())
        .await?;
        
        user_id.ok_or_else(|| {
            ApiError::ValidationError("User not found".to_string())
        })?
    } else {
        // Regular user can only set their own recovery key
        let user_id = uuid::Uuid::parse_str(&claims.sub)
            .map_err(|_| ApiError::ValidationError("Invalid user ID format".to_string()))?;

        // Verify the email matches the authenticated user
        let user_email: Option<String> = sqlx::query_scalar(
            "SELECT email FROM users WHERE id = $1"
        )
        .bind(user_id)
        .fetch_optional(pool.as_ref())
        .await?;

        match user_email {
            Some(email) if email == recovery_req.email => user_id,
            Some(_) => {
                warn!("User {} attempted to set recovery key for different user {}", claims.sub, recovery_req.email);
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

    debug!("Recovery key updated for user: {}", user_id);
    Ok(HttpResponse::Ok().json(json!({"message": "Recovery key updated"})))
}

#[utoipa::path(
    get,
    path = "/api/user/public-key/{email}",
    tag = "users",
    security(("bearerAuth" = [])),
    params(
        ("email" = String, Path, description = "User email")
    ),
    responses(
        (status = 200, description = "User's public key retrieved", body = PublicKeyResponse),
        (status = 401, description = "Unauthorized"),
        (status = 404, description = "User not found")
    )
)]
pub async fn get_user_public_key_by_email(
    path: web::Path<String>,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, ApiError> {
    let email = path.into_inner();

    let public_key: Option<String> = sqlx::query_scalar(
        "SELECT public_key FROM users WHERE email = $1"
    )
    .bind(&email)
    .fetch_optional(pool.as_ref())
    .await?;

    match public_key {
        Some(key) => {
            debug!("Public key requested for user: {}", email);
            Ok(HttpResponse::Ok().json(PublicKeyResponse { public_key: key }))
        }
        None => {
            warn!("Public key requested for non-existent user: {}", email);
            Ok(HttpResponse::NotFound().json(json!({"error": {"code": "USER_NOT_FOUND", "message": "User not found"}})))
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/users",
    tag = "users",
    security(("bearerAuth" = [])),
    params(
        ("name" = Option<String>, Query, description = "Filter by name (searches first_names, chosen_name, last_name, name_short)"),
        ("email" = Option<String>, Query, description = "Filter by email"),
        ("role" = Option<UserRole>, Query, description = "Filter by role")
    ),
    responses(
        (status = 200, description = "List of users", body = [User])
    )
)]
pub async fn list_users(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    query: web::Query<crate::models::UserSearchParams>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    let mut query_builder = sqlx::QueryBuilder::new(
        "SELECT id, email, role, is_superuser, public_key, first_names, chosen_name, last_name, 
         name_short, birthday, ssn, learner_number, person_oid, avatar_url, phone, address, 
         enrollment_date, graduation_date, created_at, updated_at FROM users WHERE 1=1"
    );

    // Apply access control based on user role
    match claims.role {
        crate::models::UserRole::Student => {
            // Students can only see users in their classes
            query_builder.push(" AND (id IN (SELECT DISTINCT cs2.student_id FROM class_students cs1 JOIN class_students cs2 ON cs1.class_id = cs2.class_id WHERE cs1.student_id = ");
            query_builder.push_bind(user_id);
            query_builder.push(") OR id IN (SELECT DISTINCT teacher_id FROM classes WHERE id IN (SELECT class_id FROM class_students WHERE student_id = ");
            query_builder.push_bind(user_id);
            query_builder.push(")))");
        }
        crate::models::UserRole::Teacher => {
            // Teachers can see students in their classes and other teachers
            query_builder.push(" AND (role = 'teacher' OR id IN (SELECT student_id FROM class_students WHERE class_id IN (SELECT id FROM classes WHERE teacher_id = ");
            query_builder.push_bind(user_id);
            query_builder.push(")))");
        }
        crate::models::UserRole::Principal => {
            // Principals can see all users
        }
    }

    // Apply filters
    if let Some(name) = &query.name {
        query_builder.push(" AND (first_names ILIKE ");
        query_builder.push_bind(format!("%{}%", name));
        query_builder.push(" OR chosen_name ILIKE ");
        query_builder.push_bind(format!("%{}%", name));
        query_builder.push(" OR last_name ILIKE ");
        query_builder.push_bind(format!("%{}%", name));
        query_builder.push(" OR name_short ILIKE ");
        query_builder.push_bind(format!("%{}%", name));
        query_builder.push(")");
    }

    if let Some(email) = &query.email {
        query_builder.push(" AND email ILIKE ");
        query_builder.push_bind(format!("%{}%", email));
    }

    if let Some(role) = &query.role {
        query_builder.push(" AND role = ");
        query_builder.push_bind(role);
    }

    query_builder.push(" ORDER BY COALESCE(chosen_name, first_names, email)");

    let users = query_builder
        .build_query_as::<User>()
        .fetch_all(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::from(e)
        })?;

    debug!("User {} retrieved {} users", user_id, users.len());
    Ok(HttpResponse::Ok().json(users))
}

#[utoipa::path(
    get,
    path = "/api/users/{id}",
    tag = "users",
    security(("bearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User details", body = User),
        (status = 404, description = "User not found"),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn get_user(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    let user_id = path.into_inner();

    // Check if user has permission to view other users
    if !claims.is_superuser && !matches!(claims.role, UserRole::Principal | UserRole::Teacher) {
        warn!("User {} attempted to view user details without permissions", claims.sub);
        return Err(ApiError::AuthorizationError);
    }

    let user = sqlx::query_as::<_, User>(
        "SELECT id, email, password_hash, role, is_superuser, public_key, recovery_key, 
         encrypted_private_key_blob, first_names, chosen_name, last_name, name_short, 
         birthday, ssn, learner_number, person_oid, avatar_url, phone, address, 
         enrollment_date, graduation_date, created_at, updated_at 
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
            debug!("User {} viewed details for user {}", claims.sub, user_id);
            Ok(HttpResponse::Ok().json(user))
        }
        None => {
            Ok(HttpResponse::NotFound().json(json!({"error": {"code": "USER_NOT_FOUND", "message": "User not found"}})))
        }
    }
}

#[utoipa::path(
    put,
    path = "/api/users/{id}",
    tag = "users",
    security(("bearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "User ID")
    ),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated successfully", body = User),
        (status = 404, description = "User not found"),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn update_user(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
    user_req: web::Json<UpdateUserRequest>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    let user_id = path.into_inner();
    let current_user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    // Check if user has permission to update users (can update self or has admin permissions)
    if user_id != current_user_id && !claims.is_superuser && !matches!(claims.role, UserRole::Principal) {
        warn!("User {} attempted to update user {} without permissions", claims.sub, user_id);
        return Err(ApiError::AuthorizationError);
    }

    // Build dynamic query based on provided fields
    let mut query_parts = Vec::new();
    let mut param_count = 1;

    if user_req.first_names.is_some() {
        query_parts.push(format!("first_names = ${}", param_count));
        param_count += 1;
    }
    if user_req.chosen_name.is_some() {
        query_parts.push(format!("chosen_name = ${}", param_count));
        param_count += 1;
    }
    if user_req.last_name.is_some() {
        query_parts.push(format!("last_name = ${}", param_count));
        param_count += 1;
    }
    if user_req.name_short.is_some() {
        query_parts.push(format!("name_short = ${}", param_count));
        param_count += 1;
    }
    if user_req.phone.is_some() {
        query_parts.push(format!("phone = ${}", param_count));
        param_count += 1;
    }
    if user_req.address.is_some() {
        query_parts.push(format!("address = ${}", param_count));
        param_count += 1;
    }
    if user_req.avatar_url.is_some() {
        query_parts.push(format!("avatar_url = ${}", param_count));
        param_count += 1;
    }

    if query_parts.is_empty() {
        return Err(ApiError::ValidationError("No fields to update".to_string()));
    }

    query_parts.push("updated_at = NOW()".to_string());
    
    let query = format!(
        "UPDATE users SET {} WHERE id = ${} RETURNING id, email, password_hash, role, is_superuser, public_key, recovery_key, 
         encrypted_private_key_blob, first_names, chosen_name, last_name, name_short, 
         birthday, ssn, learner_number, person_oid, avatar_url, phone, address, 
         enrollment_date, graduation_date, created_at, updated_at",
        query_parts.join(", "),
        param_count
    );

    let mut query_builder = sqlx::query_as::<_, User>(&query);

    // Bind parameters in the same order as query_parts
    if let Some(ref first_names) = user_req.first_names {
        query_builder = query_builder.bind(first_names);
    }
    if let Some(ref chosen_name) = user_req.chosen_name {
        query_builder = query_builder.bind(chosen_name);
    }
    if let Some(ref last_name) = user_req.last_name {
        query_builder = query_builder.bind(last_name);
    }
    if let Some(ref name_short) = user_req.name_short {
        query_builder = query_builder.bind(name_short);
    }
    if let Some(ref phone) = user_req.phone {
        query_builder = query_builder.bind(phone);
    }
    if let Some(ref address) = user_req.address {
        query_builder = query_builder.bind(address);
    }
    if let Some(ref avatar_url) = user_req.avatar_url {
        query_builder = query_builder.bind(avatar_url);
    }

    query_builder = query_builder.bind(user_id);

    let updated_user = query_builder
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::from(e)
        })?;

    match updated_user {
        Some(user) => {
            debug!("User {} updated user {}", claims.sub, user_id);
            Ok(HttpResponse::Ok().json(user))
        }
        None => {
            Ok(HttpResponse::NotFound().json(json!({"error": {"code": "USER_NOT_FOUND", "message": "User not found"}})))
        }
    }
}

#[utoipa::path(
    delete,
    path = "/api/users/{id}",
    tag = "users",
    security(("bearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "User ID")
    ),
    responses(
        (status = 204, description = "User deleted successfully"),
        (status = 404, description = "User not found"),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn delete_user(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    let user_id = path.into_inner();

    // Only superusers and principals can delete users
    if !claims.is_superuser && !matches!(claims.role, UserRole::Principal) {
        warn!("User {} attempted to delete user without permissions", claims.sub);
        return Err(ApiError::AuthorizationError);
    }

    let result = sqlx::query("DELETE FROM users WHERE id = $1")
        .bind(user_id)
        .execute(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::from(e)
        })?;

    if result.rows_affected() == 0 {
        Ok(HttpResponse::NotFound().json(json!({"error": {"code": "USER_NOT_FOUND", "message": "User not found"}})))
    } else {
        debug!("User {} deleted user {}", claims.sub, user_id);
        Ok(HttpResponse::NoContent().finish())
    }
}

#[utoipa::path(
    get,
    path = "/api/users/search",
    tag = "users",
    security(("bearerAuth" = [])),
    params(
        ("name" = Option<String>, Query, description = "Search by name"),
        ("email" = Option<String>, Query, description = "Search by email"),
        ("role" = Option<UserRole>, Query, description = "Filter by role")
    ),
    responses(
        (status = 200, description = "Search results", body = Vec<User>),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn search_users(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    query: web::Query<UserSearchParams>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    // Check if user has permission to search users
    if !claims.is_superuser && !matches!(claims.role, UserRole::Principal | UserRole::Teacher) {
        warn!("User {} attempted to search users without permissions", claims.sub);
        return Err(ApiError::AuthorizationError);
    }

    let mut conditions = Vec::new();
    let mut bind_values = Vec::new();

    if let Some(ref name) = query.name {
        conditions.push(format!(
            "(first_names ILIKE ${} OR chosen_name ILIKE ${} OR last_name ILIKE ${} OR name_short ILIKE ${})",
            bind_values.len() + 1, bind_values.len() + 2, bind_values.len() + 3, bind_values.len() + 4
        ));
        let search_pattern = format!("%{}%", name);
        bind_values.push(search_pattern.clone());
        bind_values.push(search_pattern.clone());
        bind_values.push(search_pattern.clone());
        bind_values.push(search_pattern);
    }

    if let Some(ref email) = query.email {
        conditions.push(format!("email ILIKE ${}", bind_values.len() + 1));
        let search_pattern = format!("%{}%", email);
        bind_values.push(search_pattern);
    }

    if let Some(ref role) = query.role {
        conditions.push(format!("role = ${}", bind_values.len() + 1));
        bind_values.push(format!("{:?}", role).to_lowercase());
    }

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    let query_str = format!(
        "SELECT id, email, password_hash, role, is_superuser, public_key, recovery_key, 
         encrypted_private_key_blob, first_names, chosen_name, last_name, name_short, 
         birthday, ssn, learner_number, person_oid, avatar_url, phone, address, 
         enrollment_date, graduation_date, created_at, updated_at 
         FROM users {} ORDER BY last_name, first_names LIMIT 50",
        where_clause
    );

    let mut query_builder = sqlx::query_as::<_, User>(&query_str);

    for value in bind_values {
        query_builder = query_builder.bind(value);
    }

    let users = query_builder
        .fetch_all(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::from(e)
        })?;

    debug!("User {} searched users with {} results", claims.sub, users.len());
    Ok(HttpResponse::Ok().json(users))
}
