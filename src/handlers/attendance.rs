use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use uuid::Uuid;
use log::error;
use sentry;

use crate::auth::extract_claims;
use crate::db::DbPool;
use crate::models::{RecordAttendanceRequest, UserRole, Attendance, UpdateAttendanceRequest};

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
    let is_enrolled: Option<i32> = sqlx::query_scalar(
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

#[utoipa::path(
    get,
    path = "/api/attendance",
    tag = "attendance",
    security(("bearerAuth" = [])),
    params(
        ("student_id" = Option<String>, Query, description = "Filter by student ID"),
        ("class_id" = Option<String>, Query, description = "Filter by class ID"),
        ("date" = Option<String>, Query, description = "Filter by date (YYYY-MM-DD)")
    ),
    responses(
        (status = 200, description = "List of attendance records", body = [Attendance])
    )
)]
pub async fn get_attendance(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    query: web::Query<crate::models::AttendanceSearchParams>,
) -> Result<HttpResponse, crate::errors::ApiError> {
    let claims = extract_claims(&req)
        .ok_or(crate::errors::ApiError::AuthenticationError)?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    let mut query_builder = sqlx::QueryBuilder::new(
        "SELECT id, student_id, class_id, status, recorded_at, recorded_by FROM attendance WHERE 1=1"
    );

    // Apply access control based on user role
    match claims.role {
        UserRole::Student => {
            // Students can only see their own attendance
            query_builder.push(" AND student_id = ");
            query_builder.push_bind(user_id);
        }
        UserRole::Teacher => {
            // Teachers can only see attendance for classes they teach
            query_builder.push(" AND class_id IN (SELECT id FROM classes WHERE teacher_id = ");
            query_builder.push_bind(user_id);
            query_builder.push(")");
        }
        UserRole::Principal => {
            // Principals can see all attendance
        }
    }

    // Apply filters
    if let Some(student_id) = &query.student_id {
        // Additional access control check for specific student
        match claims.role {
            UserRole::Student => {
                if user_id != *student_id {
                    return Err(crate::errors::ApiError::AuthorizationError);
                }
            }
            UserRole::Teacher => {
                // Teacher can only see attendance for students in their classes
                query_builder.push(" AND student_id = ");
                query_builder.push_bind(student_id);
                query_builder.push(" AND class_id IN (SELECT id FROM classes WHERE teacher_id = ");
                query_builder.push_bind(user_id);
                query_builder.push(")");
            }
            UserRole::Principal => {
                query_builder.push(" AND student_id = ");
                query_builder.push_bind(student_id);
            }
        }
    }

    if let Some(class_id) = &query.class_id {
        // Additional access control check for specific class
        match claims.role {
            UserRole::Student => {
                // Ensure student is enrolled in this class
                let enrolled = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM class_students WHERE class_id = $1 AND student_id = $2)"
                )
                .bind(class_id)
                .bind(user_id)
                .fetch_one(pool.as_ref())
                .await
                .map_err(|e| {
                    sentry::capture_error(&e);
                    crate::errors::ApiError::from(e)
                })?;

                if !enrolled {
                    return Err(crate::errors::ApiError::AuthorizationError);
                }
            }
            UserRole::Teacher => {
                // Teacher can only see attendance for their classes
                let teaches_class = sqlx::query_scalar::<_, bool>(
                    "SELECT EXISTS(SELECT 1 FROM classes WHERE id = $1 AND teacher_id = $2)"
                )
                .bind(class_id)
                .bind(user_id)
                .fetch_one(pool.as_ref())
                .await
                .map_err(|e| {
                    sentry::capture_error(&e);
                    crate::errors::ApiError::from(e)
                })?;

                if !teaches_class {
                    return Err(crate::errors::ApiError::AuthorizationError);
                }
            }
            UserRole::Principal => {
                // Principals can see all classes
            }
        }

        query_builder.push(" AND class_id = ");
        query_builder.push_bind(class_id);
    }

    if let Some(date) = &query.date {
        query_builder.push(" AND recorded_at::date = ");
        query_builder.push_bind(date);
    }

    query_builder.push(" ORDER BY recorded_at DESC");

    let attendance_records = query_builder
        .build_query_as::<crate::models::Attendance>()
        .fetch_all(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::from(e)
        })?;

    Ok(HttpResponse::Ok().json(attendance_records))
}

#[utoipa::path(
    get,
    path = "/api/attendance/student/{student_id}",
    tag = "attendance",
    security(("bearerAuth" = [])),
    params(
        ("student_id" = Uuid, Path, description = "Student ID")
    ),
    responses(
        (status = 200, description = "Student attendance records", body = [Attendance]),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn get_student_attendance(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, crate::errors::ApiError> {
    let claims = extract_claims(&req)
        .ok_or(crate::errors::ApiError::AuthenticationError)?;

    let student_id = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    // Check permissions: students can only see their own attendance
    match claims.role {
        UserRole::Student => {
            if user_id != student_id {
                return Err(crate::errors::ApiError::AuthorizationError);
            }
        }
        UserRole::Teacher => {
            // Teachers can only see attendance for students in their classes
            let has_access = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(
                    SELECT 1 FROM attendance a 
                    JOIN classes c ON a.class_id = c.id 
                    WHERE a.student_id = $1 AND c.teacher_id = $2
                )"
            )
            .bind(student_id)
            .bind(user_id)
            .fetch_one(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                crate::errors::ApiError::from(e)
            })?;

            if !has_access {
                return Err(crate::errors::ApiError::AuthorizationError);
            }
        }
        UserRole::Principal => {
            // Principals can see all attendance
        }
    }

    let attendance_records = sqlx::query_as::<_, Attendance>(
        "SELECT id, student_id, class_id, status, recorded_at, recorded_by 
         FROM attendance WHERE student_id = $1 ORDER BY recorded_at DESC"
    )
    .bind(student_id)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        crate::errors::ApiError::from(e)
    })?;

    Ok(HttpResponse::Ok().json(attendance_records))
}

#[utoipa::path(
    get,
    path = "/api/attendance/class/{class_id}",
    tag = "attendance",
    security(("bearerAuth" = [])),
    params(
        ("class_id" = Uuid, Path, description = "Class ID")
    ),
    responses(
        (status = 200, description = "Class attendance records", body = [Attendance]),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn get_class_attendance(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, crate::errors::ApiError> {
    let claims = extract_claims(&req)
        .ok_or(crate::errors::ApiError::AuthenticationError)?;

    let class_id = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    // Check permissions
    match claims.role {
        UserRole::Student => {
            // Students can only see their own attendance in the class
            let attendance_records = sqlx::query_as::<_, Attendance>(
                "SELECT id, student_id, class_id, status, recorded_at, recorded_by 
                 FROM attendance WHERE class_id = $1 AND student_id = $2 
                 ORDER BY recorded_at DESC"
            )
            .bind(class_id)
            .bind(user_id)
            .fetch_all(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                crate::errors::ApiError::from(e)
            })?;

            return Ok(HttpResponse::Ok().json(attendance_records));
        }
        UserRole::Teacher => {
            // Teachers can only see attendance for their classes
            let teaches_class = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM classes WHERE id = $1 AND teacher_id = $2)"
            )
            .bind(class_id)
            .bind(user_id)
            .fetch_one(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                crate::errors::ApiError::from(e)
            })?;

            if !teaches_class {
                return Err(crate::errors::ApiError::AuthorizationError);
            }
        }
        UserRole::Principal => {
            // Principals can see all attendance
        }
    }

    let attendance_records = sqlx::query_as::<_, Attendance>(
        "SELECT id, student_id, class_id, status, recorded_at, recorded_by 
         FROM attendance WHERE class_id = $1 ORDER BY recorded_at DESC"
    )
    .bind(class_id)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        crate::errors::ApiError::from(e)
    })?;

    Ok(HttpResponse::Ok().json(attendance_records))
}

#[utoipa::path(
    get,
    path = "/api/attendance/class/{class_id}/date/{date}",
    tag = "attendance",
    security(("bearerAuth" = [])),
    params(
        ("class_id" = Uuid, Path, description = "Class ID"),
        ("date" = String, Path, description = "Date (YYYY-MM-DD)")
    ),
    responses(
        (status = 200, description = "Attendance records for specific date", body = [Attendance]),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn get_class_attendance_by_date(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<(Uuid, String)>,
) -> Result<HttpResponse, crate::errors::ApiError> {
    let claims = extract_claims(&req)
        .ok_or(crate::errors::ApiError::AuthenticationError)?;

    let (class_id, date_str) = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    // Parse the date
    let date = chrono::NaiveDate::parse_from_str(&date_str, "%Y-%m-%d")
        .map_err(|_| crate::errors::ApiError::ValidationError("Invalid date format. Use YYYY-MM-DD".to_string()))?;

    // Check permissions
    match claims.role {
        UserRole::Student => {
            // Students can only see their own attendance in the class
            let attendance_records = sqlx::query_as::<_, Attendance>(
                "SELECT id, student_id, class_id, status, recorded_at, recorded_by 
                 FROM attendance WHERE class_id = $1 AND student_id = $2 AND recorded_at::date = $3
                 ORDER BY recorded_at DESC"
            )
            .bind(class_id)
            .bind(user_id)
            .bind(date)
            .fetch_all(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                crate::errors::ApiError::from(e)
            })?;

            return Ok(HttpResponse::Ok().json(attendance_records));
        }
        UserRole::Teacher => {
            // Teachers can only see attendance for their classes
            let teaches_class = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM classes WHERE id = $1 AND teacher_id = $2)"
            )
            .bind(class_id)
            .bind(user_id)
            .fetch_one(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                crate::errors::ApiError::from(e)
            })?;

            if !teaches_class {
                return Err(crate::errors::ApiError::AuthorizationError);
            }
        }
        UserRole::Principal => {
            // Principals can see all attendance
        }
    }

    let attendance_records = sqlx::query_as::<_, Attendance>(
        "SELECT id, student_id, class_id, status, recorded_at, recorded_by 
         FROM attendance WHERE class_id = $1 AND recorded_at::date = $2 
         ORDER BY recorded_at DESC"
    )
    .bind(class_id)
    .bind(date)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        crate::errors::ApiError::from(e)
    })?;

    Ok(HttpResponse::Ok().json(attendance_records))
}

#[utoipa::path(
    put,
    path = "/api/attendance/{id}",
    tag = "attendance",
    security(("bearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Attendance record ID")
    ),
    request_body = UpdateAttendanceRequest,
    responses(
        (status = 200, description = "Attendance updated successfully", body = Attendance),
        (status = 404, description = "Attendance record not found"),
        (status = 403, description = "Forbidden - only teachers can update attendance")
    )
)]
pub async fn update_attendance(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
    attendance_req: web::Json<UpdateAttendanceRequest>,
) -> Result<HttpResponse, crate::errors::ApiError> {
    let claims = extract_claims(&req)
        .ok_or(crate::errors::ApiError::AuthenticationError)?;

    let attendance_id = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    // Only teachers and principals can update attendance
    if !matches!(claims.role, UserRole::Teacher | UserRole::Principal) {
        return Err(crate::errors::ApiError::AuthorizationError);
    }

    // Check if the attendance record exists and if the teacher has permission to update it
    if matches!(claims.role, UserRole::Teacher) {
        let can_update = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1 FROM attendance a 
                JOIN classes c ON a.class_id = c.id 
                WHERE a.id = $1 AND c.teacher_id = $2
            )"
        )
        .bind(attendance_id)
        .bind(user_id)
        .fetch_one(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::from(e)
        })?;

        if !can_update {
            return Err(crate::errors::ApiError::AuthorizationError);
        }
    }

    let updated_attendance = sqlx::query_as::<_, Attendance>(
        "UPDATE attendance SET status = $2 WHERE id = $1 
         RETURNING id, student_id, class_id, status, recorded_at, recorded_by"
    )
    .bind(attendance_id)
    .bind(&attendance_req.status)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        crate::errors::ApiError::from(e)
    })?;

    match updated_attendance {
        Some(attendance) => Ok(HttpResponse::Ok().json(attendance)),
        None => Ok(HttpResponse::NotFound().json(json!({"error": {"code": "ATTENDANCE_NOT_FOUND", "message": "Attendance record not found"}}))),
    }
}

#[utoipa::path(
    delete,
    path = "/api/attendance/{id}",
    tag = "attendance",
    security(("bearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Attendance record ID")
    ),
    responses(
        (status = 204, description = "Attendance record deleted successfully"),
        (status = 404, description = "Attendance record not found"),
        (status = 403, description = "Forbidden - only teachers can delete attendance")
    )
)]
pub async fn delete_attendance(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, crate::errors::ApiError> {
    let claims = extract_claims(&req)
        .ok_or(crate::errors::ApiError::AuthenticationError)?;

    let attendance_id = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    // Only teachers and principals can delete attendance
    if !matches!(claims.role, UserRole::Teacher | UserRole::Principal) {
        return Err(crate::errors::ApiError::AuthorizationError);
    }

    // Check if the attendance record exists and if the teacher has permission to delete it
    if matches!(claims.role, UserRole::Teacher) {
        let can_delete = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1 FROM attendance a 
                JOIN classes c ON a.class_id = c.id 
                WHERE a.id = $1 AND c.teacher_id = $2
            )"
        )
        .bind(attendance_id)
        .bind(user_id)
        .fetch_one(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::from(e)
        })?;

        if !can_delete {
            return Err(crate::errors::ApiError::AuthorizationError);
        }
    }

    let result = sqlx::query("DELETE FROM attendance WHERE id = $1")
        .bind(attendance_id)
        .execute(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::from(e)
        })?;

    if result.rows_affected() == 0 {
        Ok(HttpResponse::NotFound().json(json!({"error": {"code": "ATTENDANCE_NOT_FOUND", "message": "Attendance record not found"}})))
    } else {
        Ok(HttpResponse::NoContent().finish())
    }
}
