use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use uuid::Uuid;
use log::error;
use sentry;

use crate::auth::extract_claims;
use crate::db::DbPool;
use crate::models::{AssignGradeRequest, UserRole, Grade, UpdateGradeRequest};

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

#[utoipa::path(
    get,
    path = "/api/grades",
    tag = "grades",
    security(("bearerAuth" = [])),
    params(
        ("student_id" = Option<String>, Query, description = "Filter by student ID"),
        ("class_id" = Option<String>, Query, description = "Filter by class ID")
    ),
    responses(
        (status = 200, description = "List of grades", body = [Grade])
    )
)]
pub async fn get_grades(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    query: web::Query<crate::models::GradeSearchParams>,
) -> Result<HttpResponse, crate::errors::ApiError> {
    let claims = extract_claims(&req)
        .ok_or(crate::errors::ApiError::AuthenticationError)?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    let mut query_builder = sqlx::QueryBuilder::new(
        "SELECT id, student_id, class_id, teacher_id, grade, assigned_at FROM grades WHERE 1=1"
    );

    // Apply access control based on user role
    match claims.role {
        UserRole::Student => {
            // Students can only see their own grades
            query_builder.push(" AND student_id = ");
            query_builder.push_bind(user_id);
        }
        UserRole::Teacher => {
            // Teachers can only see grades for classes they teach
            query_builder.push(" AND class_id IN (SELECT id FROM classes WHERE teacher_id = ");
            query_builder.push_bind(user_id);
            query_builder.push(")");
        }
        UserRole::Principal => {
            // Principals can see all grades
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
                // Teacher can only see grades for students in their classes
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
                // Teacher can only see grades for their classes
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

    query_builder.push(" ORDER BY assigned_at DESC");

    let grades = query_builder
        .build_query_as::<crate::models::Grade>()
        .fetch_all(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::from(e)
        })?;

    Ok(HttpResponse::Ok().json(grades))
}

#[utoipa::path(
    get,
    path = "/api/grades/student/{student_id}",
    tag = "grades",
    security(("bearerAuth" = [])),
    params(
        ("student_id" = Uuid, Path, description = "Student ID")
    ),
    responses(
        (status = 200, description = "Student grades", body = [Grade]),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn get_student_grades(
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

    // Check permissions: students can only see their own grades
    match claims.role {
        UserRole::Student => {
            if user_id != student_id {
                return Err(crate::errors::ApiError::AuthorizationError);
            }
        }
        UserRole::Teacher => {
            // Teachers can only see grades for students in their classes
            let has_access = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(
                    SELECT 1 FROM grades g 
                    JOIN classes c ON g.class_id = c.id 
                    WHERE g.student_id = $1 AND c.teacher_id = $2
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
            // Principals can see all grades
        }
    }

    let grades = sqlx::query_as::<_, Grade>(
        "SELECT id, student_id, class_id, teacher_id, grade, assigned_at 
         FROM grades WHERE student_id = $1 ORDER BY assigned_at DESC"
    )
    .bind(student_id)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        crate::errors::ApiError::from(e)
    })?;

    Ok(HttpResponse::Ok().json(grades))
}

#[utoipa::path(
    get,
    path = "/api/grades/class/{class_id}",
    tag = "grades",
    security(("bearerAuth" = [])),
    params(
        ("class_id" = Uuid, Path, description = "Class ID")
    ),
    responses(
        (status = 200, description = "Class grades", body = [Grade]),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn get_class_grades(
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
            // Students can only see their own grades in the class
            let grades = sqlx::query_as::<_, Grade>(
                "SELECT id, student_id, class_id, teacher_id, grade, assigned_at 
                 FROM grades WHERE class_id = $1 AND student_id = $2 
                 ORDER BY assigned_at DESC"
            )
            .bind(class_id)
            .bind(user_id)
            .fetch_all(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                crate::errors::ApiError::from(e)
            })?;

            return Ok(HttpResponse::Ok().json(grades));
        }
        UserRole::Teacher => {
            // Teachers can only see grades for their classes
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
            // Principals can see all grades
        }
    }

    let grades = sqlx::query_as::<_, Grade>(
        "SELECT id, student_id, class_id, teacher_id, grade, assigned_at 
         FROM grades WHERE class_id = $1 ORDER BY assigned_at DESC"
    )
    .bind(class_id)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        crate::errors::ApiError::from(e)
    })?;

    Ok(HttpResponse::Ok().json(grades))
}

#[utoipa::path(
    put,
    path = "/api/grades/{id}",
    tag = "grades",
    security(("bearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Grade ID")
    ),
    request_body = UpdateGradeRequest,
    responses(
        (status = 200, description = "Grade updated successfully", body = Grade),
        (status = 404, description = "Grade not found"),
        (status = 403, description = "Forbidden - only teachers can update grades")
    )
)]
pub async fn update_grade(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
    grade_req: web::Json<UpdateGradeRequest>,
) -> Result<HttpResponse, crate::errors::ApiError> {
    let claims = extract_claims(&req)
        .ok_or(crate::errors::ApiError::AuthenticationError)?;

    let grade_id = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    // Only teachers and principals can update grades
    if !matches!(claims.role, UserRole::Teacher | UserRole::Principal) {
        return Err(crate::errors::ApiError::AuthorizationError);
    }

    // Check if the grade exists and if the teacher has permission to update it
    if matches!(claims.role, UserRole::Teacher) {
        let can_update = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1 FROM grades g 
                JOIN classes c ON g.class_id = c.id 
                WHERE g.id = $1 AND c.teacher_id = $2
            )"
        )
        .bind(grade_id)
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

    let updated_grade = sqlx::query_as::<_, Grade>(
        "UPDATE grades SET grade = $2 WHERE id = $1 
         RETURNING id, student_id, class_id, teacher_id, grade, assigned_at"
    )
    .bind(grade_id)
    .bind(&grade_req.grade)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        crate::errors::ApiError::from(e)
    })?;

    match updated_grade {
        Some(grade) => Ok(HttpResponse::Ok().json(grade)),
        None => Ok(HttpResponse::NotFound().json(json!({"error": {"code": "GRADE_NOT_FOUND", "message": "Grade not found"}}))),
    }
}

#[utoipa::path(
    delete,
    path = "/api/grades/{id}",
    tag = "grades",
    security(("bearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Grade ID")
    ),
    responses(
        (status = 204, description = "Grade deleted successfully"),
        (status = 404, description = "Grade not found"),
        (status = 403, description = "Forbidden - only teachers can delete grades")
    )
)]
pub async fn delete_grade(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
) -> Result<HttpResponse, crate::errors::ApiError> {
    let claims = extract_claims(&req)
        .ok_or(crate::errors::ApiError::AuthenticationError)?;

    let grade_id = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    // Only teachers and principals can delete grades
    if !matches!(claims.role, UserRole::Teacher | UserRole::Principal) {
        return Err(crate::errors::ApiError::AuthorizationError);
    }

    // Check if the grade exists and if the teacher has permission to delete it
    if matches!(claims.role, UserRole::Teacher) {
        let can_delete = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(
                SELECT 1 FROM grades g 
                JOIN classes c ON g.class_id = c.id 
                WHERE g.id = $1 AND c.teacher_id = $2
            )"
        )
        .bind(grade_id)
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

    let result = sqlx::query("DELETE FROM grades WHERE id = $1")
        .bind(grade_id)
        .execute(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::from(e)
        })?;

    if result.rows_affected() == 0 {
        Ok(HttpResponse::NotFound().json(json!({"error": {"code": "GRADE_NOT_FOUND", "message": "Grade not found"}})))
    } else {
        Ok(HttpResponse::NoContent().finish())
    }
}
