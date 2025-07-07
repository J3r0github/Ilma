use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use uuid::Uuid;
use log::error;
use sentry;

use crate::auth::extract_claims;
use crate::db::DbPool;
use crate::models::{Permission, PermissionSet, AssignPermissionsRequest, UserRole};

#[utoipa::path(
    get,
    path = "/api/permissions",
    tag = "permissions",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "List of permissions", body = [Permission])
    )
)]
pub async fn list_permissions(
    req: HttpRequest,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, actix_web::Error> {
    let _claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    let permissions = sqlx::query_as::<_, Permission>(
        "SELECT id, name, description FROM permissions ORDER BY name"
    )
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        sentry::capture_error(&e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    Ok(HttpResponse::Ok().json(permissions))
}

#[utoipa::path(
    get,
    path = "/api/permissions/sets",
    tag = "permissions",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "List of permission sets with permissions", body = [PermissionSet])
    )
)]
pub async fn list_permission_sets(
    req: HttpRequest,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, actix_web::Error> {
    let _claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    // Get all permission sets
    let sets: Vec<(i32, String)> = sqlx::query_as(
        "SELECT id, name FROM permission_sets ORDER BY name"
    )
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    let mut permission_sets = Vec::new();

    for (set_id, set_name) in sets {
        let permissions = sqlx::query_as::<_, Permission>(
            "SELECT p.id, p.name, p.description 
             FROM permissions p 
             JOIN permission_set_permissions psp ON p.id = psp.permission_id 
             WHERE psp.permission_set_id = $1 
             ORDER BY p.name"
        )
        .bind(set_id)
        .fetch_all(pool.as_ref())
        .await
        .map_err(|e| {
            error!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

        permission_sets.push(PermissionSet {
            id: set_id,
            name: set_name,
            permissions,
        });
    }

    Ok(HttpResponse::Ok().json(permission_sets))
}

#[utoipa::path(
    get,
    path = "/api/users/{id}/permissions",
    tag = "permissions",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, description = "User UUID")
    ),
    responses(
        (status = 200, description = "Permissions list", body = [Permission])
    )
)]
pub async fn get_user_permissions(
    req: HttpRequest,
    path: web::Path<Uuid>,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, actix_web::Error> {
    let _claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    let user_id = path.into_inner();

    let permissions = sqlx::query_as::<_, Permission>(
        "SELECT p.id, p.name, p.description 
         FROM permissions p 
         JOIN user_permissions up ON p.id = up.permission_id 
         WHERE up.user_id = $1 
         ORDER BY p.name"
    )
    .bind(user_id)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    Ok(HttpResponse::Ok().json(permissions))
}

#[utoipa::path(
    post,
    path = "/api/users/{id}/permissions",
    tag = "permissions",
    security(("bearerAuth" = [])),
    params(
        ("id" = String, Path, description = "User UUID")
    ),
    request_body = AssignPermissionsRequest,
    responses(
        (status = 204, description = "Permissions assigned"),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn assign_user_permissions(
    req: HttpRequest,
    path: web::Path<Uuid>,
    pool: web::Data<DbPool>,
    permission_req: web::Json<AssignPermissionsRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    // Check if user has permission to assign permissions (superuser or principal)
    if !claims.is_superuser && !matches!(claims.role, crate::models::UserRole::Principal) {
        return Ok(HttpResponse::Forbidden().json(json!({"error": "Insufficient permissions"})));
    }

    let user_id = path.into_inner();

    // Start a transaction
    let mut tx = pool.begin().await.map_err(|e| {
        error!("Transaction error: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    // Clear existing permissions
    sqlx::query("DELETE FROM user_permissions WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    // Insert new permissions
    for permission_id in &permission_req.permission_ids {
        sqlx::query("INSERT INTO user_permissions (user_id, permission_id) VALUES ($1, $2)")
            .bind(user_id)
            .bind(permission_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("Database error: {}", e);
                actix_web::error::ErrorInternalServerError("Database error")
            })?;
    }

    tx.commit().await.map_err(|e| {
        error!("Transaction commit error: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    Ok(HttpResponse::NoContent().finish())
}
