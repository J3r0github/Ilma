use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use sqlx::PgPool;
use utoipa::path;
use uuid::Uuid;
use log::error;
use sentry;

use crate::auth::extract_claims;
use crate::db::DbPool;
use crate::models::{Class, CreateClassRequest, AddStudentRequest, UserRole};

#[utoipa::path(
    get,
    path = "/api/classes",
    tag = "classes",
    security(("bearerAuth" = [])),
    responses(
        (status = 200, description = "List of classes", body = [Class])
    )
)]
pub async fn list_classes(
    req: HttpRequest,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, actix_web::Error> {
    let claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            actix_web::error::ErrorBadRequest("Invalid user ID format")
        })?;

    let classes = match claims.role {
        UserRole::Teacher => {
            // Teachers see classes they teach
            sqlx::query_as::<_, Class>(
                "SELECT id, name, teacher_id, created_at FROM classes WHERE teacher_id = $1 ORDER BY name"
            )
            .bind(user_id)
            .fetch_all(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                actix_web::error::ErrorInternalServerError("Database error")
            })
        }
        UserRole::Student => {
            // Students see classes they're enrolled in
            sqlx::query_as::<_, Class>(
                "SELECT c.id, c.name, c.teacher_id, c.created_at 
                 FROM classes c 
                 JOIN class_students cs ON c.id = cs.class_id 
                 WHERE cs.student_id = $1 
                 ORDER BY c.name"
            )
            .bind(user_id)
            .fetch_all(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                actix_web::error::ErrorInternalServerError("Database error")
            })
        }
        UserRole::Principal => {
            // Principals see all classes
            sqlx::query_as::<_, Class>(
                "SELECT id, name, teacher_id, created_at FROM classes ORDER BY name"
            )
            .fetch_all(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                actix_web::error::ErrorInternalServerError("Database error")
            })
        }
    }?;

    Ok(HttpResponse::Ok().json(classes))
}

#[utoipa::path(
    post,
    path = "/api/classes",
    tag = "classes",
    security(("bearerAuth" = [])),
    request_body = CreateClassRequest,
    responses(
        (status = 201, description = "Class created"),
        (status = 403, description = "Forbidden - only teachers can create classes")
    )
)]
pub async fn create_class(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    class_req: web::Json<CreateClassRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    // Only teachers and principals can create classes
    if !matches!(claims.role, UserRole::Teacher | UserRole::Principal) {
        return Ok(HttpResponse::Forbidden().json(json!({"error": "Only teachers can create classes"})));
    }

    let teacher_id = Uuid::parse_str(&claims.sub).unwrap();
    let class_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO classes (id, name, teacher_id) VALUES ($1, $2, $3)"
    )
    .bind(class_id)
    .bind(&class_req.name)
    .bind(teacher_id)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to create class")
    })?;

    Ok(HttpResponse::Created().json(json!({"message": "Class created successfully", "id": class_id})))
}

#[utoipa::path(
    post,
    path = "/api/classes/{class_id}/students",
    tag = "classes",
    security(("bearerAuth" = [])),
    params(
        ("class_id" = String, Path, description = "Class UUID")
    ),
    request_body = AddStudentRequest,
    responses(
        (status = 200, description = "Student added to class"),
        (status = 403, description = "Forbidden - only class teacher can add students"),
        (status = 404, description = "Class not found")
    )
)]
pub async fn add_student_to_class(
    req: HttpRequest,
    path: web::Path<Uuid>,
    pool: web::Data<DbPool>,
    student_req: web::Json<AddStudentRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    let class_id = path.into_inner();
    let teacher_id = Uuid::parse_str(&claims.sub).unwrap();

    // Check if the user is the teacher of this class or is a principal
    let is_class_teacher = if matches!(claims.role, UserRole::Principal) {
        true
    } else {
        let teacher_check: Option<Uuid> = sqlx::query_scalar(
            "SELECT teacher_id FROM classes WHERE id = $1"
        )
        .bind(class_id)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| {
            error!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

        match teacher_check {
            Some(id) => id == teacher_id,
            None => return Ok(HttpResponse::NotFound().json(json!({"error": "Class not found"}))),
        }
    };

    if !is_class_teacher {
        return Ok(HttpResponse::Forbidden().json(json!({"error": "Only the class teacher can add students"})));
    }

    // Add student to class (ignore if already exists)
    sqlx::query(
        "INSERT INTO class_students (class_id, student_id) VALUES ($1, $2) ON CONFLICT DO NOTHING"
    )
    .bind(class_id)
    .bind(student_req.student_id)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to add student to class")
    })?;

    Ok(HttpResponse::Ok().json(json!({"message": "Student added to class successfully"})))
}
