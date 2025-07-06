use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use sqlx::PgPool;
use utoipa::path;
use uuid::Uuid;
use log::error;
use sentry;

use crate::auth::extract_claims;
use crate::db::DbPool;
use crate::models::{RecordAttendanceRequest, UserRole};

#[utoipa::path(
    post,
    path = "/api/attendance",
    tag = "attendance",
    security(("bearerAuth" = [])),
    request_body = RecordAttendanceRequest,
    responses(
        (status = 200, description = "Attendance recorded"),
        (status = 403, description = "Forbidden - only teachers can record attendance")
    )
)]
pub async fn record_attendance(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    attendance_req: web::Json<RecordAttendanceRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    // Only teachers and principals can record attendance
    if !matches!(claims.role, UserRole::Teacher | UserRole::Principal) {
        return Ok(HttpResponse::Forbidden().json(json!({"error": "Only teachers can record attendance"})));
    }

    let recorder_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            actix_web::error::ErrorBadRequest("Invalid user ID format")
        })?;

    // Check if the teacher teaches this class (unless they're a principal)
    if !matches!(claims.role, UserRole::Principal) {
        let teaches_class: Option<Uuid> = sqlx::query_scalar(
            "SELECT teacher_id FROM classes WHERE id = $1"
        )
        .bind(attendance_req.class_id)
        .fetch_optional(pool.as_ref())
        .await
        .map_err(|e| {
            error!("Database error: {}", e);
            sentry::capture_error(&e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

        match teaches_class {
            Some(id) if id == recorder_id => {}, // OK
            Some(_) => return Ok(HttpResponse::Forbidden().json(json!({"error": "You can only record attendance for classes you teach"}))),
            None => return Ok(HttpResponse::NotFound().json(json!({"error": "Class not found"}))),
        }
    }

    // Check if student is enrolled in the class
    let is_enrolled: Option<()> = sqlx::query_scalar(
        "SELECT 1 FROM class_students WHERE class_id = $1 AND student_id = $2"
    )
    .bind(attendance_req.class_id)
    .bind(attendance_req.student_id)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    if is_enrolled.is_none() {
        return Ok(HttpResponse::BadRequest().json(json!({"error": "Student is not enrolled in this class"})));
    }

    let attendance_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO attendance (id, student_id, class_id, status, recorded_by) 
         VALUES ($1, $2, $3, $4, $5)"
    )
    .bind(attendance_id)
    .bind(attendance_req.student_id)
    .bind(attendance_req.class_id)
    .bind(&attendance_req.status)
    .bind(recorder_id)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Failed to record attendance")
    })?;

    Ok(HttpResponse::Ok().json(json!({"message": "Attendance recorded successfully", "id": attendance_id})))
}
