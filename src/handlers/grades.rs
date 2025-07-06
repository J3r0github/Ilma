use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use sqlx::PgPool;
use utoipa::path;
use uuid::Uuid;
use log::error;
use sentry;

use crate::auth::extract_claims;
use crate::db::DbPool;
use crate::models::{AssignGradeRequest, UserRole};

#[utoipa::path(
    post,
    path = "/api/grades",
    tag = "grades",
    security(("bearerAuth" = [])),
    request_body = AssignGradeRequest,
    responses(
        (status = 201, description = "Grade assigned"),
        (status = 403, description = "Forbidden - only teachers can assign grades")
    )
)]
pub async fn assign_grade(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    grade_req: web::Json<AssignGradeRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    // Only teachers and principals can assign grades
    if !matches!(claims.role, UserRole::Teacher | UserRole::Principal) {
        return Ok(HttpResponse::Forbidden().json(json!({"error": "Only teachers can assign grades"})));
    }

    let teacher_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            actix_web::error::ErrorBadRequest("Invalid user ID format")
        })?;

    // Check if the teacher teaches this class (unless they're a principal)
    if !matches!(claims.role, UserRole::Principal) {
        let teaches_class: Option<Uuid> = sqlx::query_scalar(
            "SELECT teacher_id FROM classes WHERE id = $1"
        )
        .bind(grade_req.class_id)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| {
            error!("Database error: {}", e);
            sentry::capture_error(&e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

        match teaches_class {
            Some(id) if id == teacher_id => {}, // OK
            Some(_) => return Ok(HttpResponse::Forbidden().json(json!({"error": "You can only assign grades for classes you teach"}))),
            None => return Ok(HttpResponse::NotFound().json(json!({"error": "Class not found"}))),
        }
    }

    // Check if student is enrolled in the class
    let is_enrolled: Option<()> = sqlx::query_scalar(
        "SELECT 1 FROM class_students WHERE class_id = $1 AND student_id = $2"
    )
    .bind(grade_req.class_id)
    .bind(grade_req.student_id)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    if is_enrolled.is_none() {
        return Ok(HttpResponse::BadRequest().json(json!({"error": "Student is not enrolled in this class"})));
    }

    let grade_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO grades (id, student_id, class_id, teacher_id, grade) 
         VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(grade_id)
    .bind(grade_req.student_id)
    .bind(grade_req.class_id)
    .bind(teacher_id)
    .bind(&grade_req.grade)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to assign grade")
    })?;

    Ok(HttpResponse::Created().json(json!({"message": "Grade assigned successfully", "id": grade_id})))
}
