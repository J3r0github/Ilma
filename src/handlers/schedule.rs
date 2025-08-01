use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use uuid::Uuid;
use log::debug;
use sentry;

use crate::auth::extract_claims;
use crate::db::DbPool;
use crate::models::{ScheduleEvent, CreateScheduleEventRequest, ScheduleSearchParams, UserRole, UpdateScheduleEventRequest};
use crate::errors::ApiError;

#[utoipa::path(
    get,
    path = "/api/schedule",
    tag = "schedule",
    security(("bearerAuth" = [])),
    params(
        ("class_id" = Option<String>, Query, description = "Filter by class ID"),
        ("student_id" = Option<String>, Query, description = "Filter by student ID"),
        ("date_from" = Option<String>, Query, description = "Filter events from this date (YYYY-MM-DD)"),
        ("date_to" = Option<String>, Query, description = "Filter events to this date (YYYY-MM-DD)")
    ),
    responses(
        (status = 200, description = "List of schedule events", body = [ScheduleEvent])
    )
)]
pub async fn get_schedule(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    query: web::Query<ScheduleSearchParams>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    let mut query_builder = sqlx::QueryBuilder::new(
        "SELECT id, title, description, start_time, end_time, date, class_id, teacher_id, created_at, updated_at FROM schedule_events WHERE 1=1"
    );

    // Apply access control based on user role
    match claims.role {
        UserRole::Student => {
            // Students can only see events for classes they're enrolled in
            query_builder.push(" AND (class_id IN (SELECT class_id FROM class_students WHERE student_id = ");
            query_builder.push_bind(user_id);
            query_builder.push(") OR class_id IS NULL)");
        }
        UserRole::Teacher => {
            // Teachers can see events for classes they teach
            query_builder.push(" AND (teacher_id = ");
            query_builder.push_bind(user_id);
            query_builder.push(" OR class_id IN (SELECT id FROM classes WHERE teacher_id = ");
            query_builder.push_bind(user_id);
            query_builder.push(") OR class_id IS NULL)");
        }
        UserRole::Principal => {
            // Principals can see all events
        }
    }

    // Apply filters
    if let Some(class_id) = &query.class_id {
        query_builder.push(" AND class_id = ");
        query_builder.push_bind(class_id);
    }

    if let Some(student_id) = &query.student_id {
        // Only allow if user has permission to view this student's data
        match claims.role {
            UserRole::Student => {
                if user_id != *student_id {
                    return Err(ApiError::AuthorizationError);
                }
            }
            UserRole::Teacher => {
                // Teacher can only see students in their classes
                query_builder.push(" AND class_id IN (SELECT class_id FROM class_students WHERE student_id = ");
                query_builder.push_bind(student_id);
                query_builder.push(" AND class_id IN (SELECT id FROM classes WHERE teacher_id = ");
                query_builder.push_bind(user_id);
                query_builder.push("))");
            }
            UserRole::Principal => {
                // Principals can see all students
                query_builder.push(" AND class_id IN (SELECT class_id FROM class_students WHERE student_id = ");
                query_builder.push_bind(student_id);
                query_builder.push(")");
            }
        }
    }

    if let Some(date_from) = &query.date_from {
        query_builder.push(" AND date >= ");
        query_builder.push_bind(date_from);
    }

    if let Some(date_to) = &query.date_to {
        query_builder.push(" AND date <= ");
        query_builder.push_bind(date_to);
    }

    query_builder.push(" ORDER BY date, start_time");

    let events = query_builder
        .build_query_as::<ScheduleEvent>()
        .fetch_all(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::from(e)
        })?;

    debug!("User {} retrieved {} schedule events", user_id, events.len());
    Ok(HttpResponse::Ok().json(events))
}

#[utoipa::path(
    post,
    path = "/api/schedule",
    tag = "schedule",
    security(("bearerAuth" = [])),
    request_body = CreateScheduleEventRequest,
    responses(
        (status = 201, description = "Schedule event created"),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn create_schedule_event(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    event_req: web::Json<CreateScheduleEventRequest>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    // Only teachers and principals can create schedule events
    match claims.role {
        UserRole::Student => {
            return Err(ApiError::AuthorizationError);
        }
        UserRole::Teacher => {
            // Teachers can only create events for their classes
            if let Some(class_id) = event_req.class_id {
                let class_teacher = sqlx::query_scalar::<_, Uuid>(
                    "SELECT teacher_id FROM classes WHERE id = $1"
                )
                .bind(class_id)
                .fetch_optional(pool.as_ref())
                .await
                .map_err(|e| {
                    sentry::capture_error(&e);
                    ApiError::from(e)
                })?;

                if class_teacher != Some(user_id) {
                    return Err(ApiError::AuthorizationError);
                }
            }
        }
        UserRole::Principal => {
            // Principals can create events for any class
        }
    }

    let event_id = Uuid::new_v4();

    sqlx::query(
        "INSERT INTO schedule_events (id, title, description, start_time, end_time, date, class_id, teacher_id) 
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)"
    )
    .bind(event_id)
    .bind(&event_req.title)
    .bind(&event_req.description)
    .bind(&event_req.start_time)
    .bind(&event_req.end_time)
    .bind(&event_req.date)
    .bind(&event_req.class_id)
    .bind(user_id)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        ApiError::from(e)
    })?;

    debug!("User {} created schedule event {}", user_id, event_id);
    Ok(HttpResponse::Created().json(json!({
        "message": "Schedule event created successfully",
        "id": event_id
    })))
}

#[utoipa::path(
    put,
    path = "/api/schedule/events/{id}",
    tag = "schedule",
    security(("bearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Schedule event ID")
    ),
    request_body = UpdateScheduleEventRequest,
    responses(
        (status = 200, description = "Schedule event updated successfully", body = ScheduleEvent),
        (status = 404, description = "Schedule event not found"),
        (status = 403, description = "Forbidden - only teachers can update schedule events")
    )
)]
pub async fn update_schedule_event(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
    event_req: web::Json<UpdateScheduleEventRequest>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    let event_id = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    // Only teachers and principals can update schedule events
    if !matches!(claims.role, UserRole::Teacher | UserRole::Principal) {
        return Err(ApiError::AuthorizationError);
    }

    // Check if the event exists and if the teacher has permission to update it
    if matches!(claims.role, UserRole::Teacher) {
        let can_update = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1 FROM schedule_events se 
                LEFT JOIN classes c ON se.class_id = c.id 
                WHERE se.id = $1 AND (se.teacher_id = $2 OR c.teacher_id = $2)
            )"
        )
        .bind(event_id)
        .bind(user_id)
        .fetch_one(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::from(e)
        })?;

        if !can_update {
            return Err(ApiError::AuthorizationError);
        }
    }

    let updated_event = sqlx::query_as::<_, ScheduleEvent>(
        "UPDATE schedule_events 
         SET title = $2, description = $3, start_time = $4, end_time = $5, date = $6, updated_at = NOW()
         WHERE id = $1 
         RETURNING id, title, description, start_time, end_time, date, class_id, teacher_id, created_at, updated_at"
    )
    .bind(event_id)
    .bind(&event_req.title)
    .bind(&event_req.description)
    .bind(event_req.start_time)
    .bind(event_req.end_time)
    .bind(event_req.date)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        ApiError::from(e)
    })?;

    match updated_event {
        Some(event) => Ok(HttpResponse::Ok().json(event)),
        None => Ok(HttpResponse::NotFound().json(json!({"error": {"code": "EVENT_NOT_FOUND", "message": "Schedule event not found"}}))),
    }
}

#[utoipa::path(
    delete,
    path = "/api/schedule/events/{id}",
    tag = "schedule",
    security(("bearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Schedule event ID")
    ),
    responses(
        (status = 204, description = "Schedule event deleted successfully"),
        (status = 404, description = "Schedule event not found"),
        (status = 403, description = "Forbidden - only teachers can delete schedule events")
    )
)]
pub async fn delete_schedule_event(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, ApiError> {
    let claims = extract_claims(&req)
        .ok_or(ApiError::AuthenticationError)?;

    let event_id = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    // Only teachers and principals can delete schedule events
    if !matches!(claims.role, UserRole::Teacher | UserRole::Principal) {
        return Err(ApiError::AuthorizationError);
    }

    // Check if the event exists and if the teacher has permission to delete it
    if matches!(claims.role, UserRole::Teacher) {
        let can_delete = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1 FROM schedule_events se 
                LEFT JOIN classes c ON se.class_id = c.id 
                WHERE se.id = $1 AND (se.teacher_id = $2 OR c.teacher_id = $2)
            )"
        )
        .bind(event_id)
        .bind(user_id)
        .fetch_one(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::from(e)
        })?;

        if !can_delete {
            return Err(ApiError::AuthorizationError);
        }
    }

    let result = sqlx::query("DELETE FROM schedule_events WHERE id = $1")
        .bind(event_id)
        .execute(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            ApiError::from(e)
        })?;

    if result.rows_affected() == 0 {
        Ok(HttpResponse::NotFound().json(json!({"error": {"code": "EVENT_NOT_FOUND", "message": "Schedule event not found"}})))
    } else {
        Ok(HttpResponse::NoContent().finish())
    }
}
