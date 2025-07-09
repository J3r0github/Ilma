use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use uuid::Uuid;
use log::error;
use sentry;

use crate::auth::extract_claims;
use crate::db::DbPool;
use crate::models::{Class, CreateClassRequest, AddStudentRequest, UpdateClassRequest, UserRole, User};

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

#[utoipa::path(
    get,
    path = "/api/classes/{class_id}/students",
    tag = "classes",
    security(("bearerAuth" = [])),
    params(
        ("class_id" = String, Path, description = "Class UUID")
    ),
    responses(
        (status = 200, description = "List of students in the class", body = [User]),
        (status = 403, description = "Forbidden - insufficient permissions"),
        (status = 404, description = "Class not found")
    )
)]
pub async fn get_class_students(
    req: HttpRequest,
    path: web::Path<Uuid>,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, actix_web::Error> {
    let claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    let class_id = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            actix_web::error::ErrorBadRequest("Invalid user ID format")
        })?;

    // Check if user has permission to view this class
    match claims.role {
        UserRole::Student => {
            // Students can only see students in their own classes
            let enrolled = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM class_students WHERE class_id = $1 AND student_id = $2)"
            )
            .bind(class_id)
            .bind(user_id)
            .fetch_one(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                actix_web::error::ErrorInternalServerError("Database error")
            })?;

            if !enrolled {
                return Ok(HttpResponse::Forbidden().json(json!({"error": "Access denied"})));
            }
        }
        UserRole::Teacher => {
            // Teachers can only see students in their classes
            let is_teacher = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM classes WHERE id = $1 AND teacher_id = $2)"
            )
            .bind(class_id)
            .bind(user_id)
            .fetch_one(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                actix_web::error::ErrorInternalServerError("Database error")
            })?;

            if !is_teacher {
                return Ok(HttpResponse::Forbidden().json(json!({"error": "Access denied"})));
            }
        }
        UserRole::Principal => {
            // Principals can see all classes
        }
    }

    let students = sqlx::query_as::<_, crate::models::User>(
        "SELECT u.id, u.email, u.password_hash, u.role, u.is_superuser, u.public_key, u.recovery_key, u.encrypted_private_key_blob,
         u.first_names, u.chosen_name, u.last_name, u.name_short, 
         u.birthday, u.ssn, u.learner_number, u.person_oid, u.avatar_url, u.phone, u.address, 
         u.enrollment_date, u.graduation_date, u.created_at, u.updated_at
         FROM users u
         JOIN class_students cs ON u.id = cs.student_id
         WHERE cs.class_id = $1
         ORDER BY u.email"
    )
    .bind(class_id)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    Ok(HttpResponse::Ok().json(students))
}

#[utoipa::path(
    delete,
    path = "/api/classes/{class_id}/students/{student_id}",
    tag = "classes",
    security(("bearerAuth" = [])),
    params(
        ("class_id" = String, Path, description = "Class UUID"),
        ("student_id" = String, Path, description = "Student UUID")
    ),
    responses(
        (status = 204, description = "Student removed from class"),
        (status = 403, description = "Forbidden - insufficient permissions"),
        (status = 404, description = "Class or student not found")
    )
)]
pub async fn remove_student_from_class(
    req: HttpRequest,
    path: web::Path<(Uuid, Uuid)>,
    pool: web::Data<DbPool>,
) -> Result<HttpResponse, actix_web::Error> {
    let claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    let (class_id, student_id) = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            actix_web::error::ErrorBadRequest("Invalid user ID format")
        })?;

    // Check if user has permission to remove students from this class
    match claims.role {
        UserRole::Student => {
            return Ok(HttpResponse::Forbidden().json(json!({"error": "Students cannot remove other students"})));
        }
        UserRole::Teacher => {
            // Teachers can only remove students from their own classes
            let is_teacher = sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM classes WHERE id = $1 AND teacher_id = $2)"
            )
            .bind(class_id)
            .bind(user_id)
            .fetch_one(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                actix_web::error::ErrorInternalServerError("Database error")
            })?;

            if !is_teacher {
                return Ok(HttpResponse::Forbidden().json(json!({"error": "Access denied"})));
            }
        }
        UserRole::Principal => {
            // Principals can remove students from any class
        }
    }

    let rows_affected = sqlx::query(
        "DELETE FROM class_students WHERE class_id = $1 AND student_id = $2"
    )
    .bind(class_id)
    .bind(student_id)
    .execute(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?
    .rows_affected();

    if rows_affected == 0 {
        return Ok(HttpResponse::NotFound().json(json!({"error": "Student not found in class"})));
    }

    Ok(HttpResponse::NoContent().finish())
}

#[utoipa::path(
    put,
    path = "/api/classes/{id}",
    tag = "classes",
    security(("bearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Class ID")
    ),
    request_body = UpdateClassRequest,
    responses(
        (status = 200, description = "Class updated successfully", body = Class),
        (status = 404, description = "Class not found"),
        (status = 403, description = "Forbidden - only teachers can update their classes")
    )
)]
pub async fn update_class(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    path: web::Path<Uuid>,
    class_req: web::Json<UpdateClassRequest>,
) -> Result<HttpResponse, crate::errors::ApiError> {
    let claims = extract_claims(&req)
        .ok_or(crate::errors::ApiError::AuthenticationError)?;

    let class_id = path.into_inner();
    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::ValidationError("Invalid user ID format".to_string())
        })?;

    // Only teachers and principals can update classes
    if !matches!(claims.role, UserRole::Teacher | UserRole::Principal) {
        return Err(crate::errors::ApiError::AuthorizationError);
    }

    // Teachers can only update their own classes
    if matches!(claims.role, UserRole::Teacher) {
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

    let updated_class = sqlx::query_as::<_, Class>(
        "UPDATE classes SET name = $2 WHERE id = $1 
         RETURNING id, name, teacher_id, created_at"
    )
    .bind(class_id)
    .bind(&class_req.name)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        crate::errors::ApiError::from(e)
    })?;

    match updated_class {
        Some(class) => Ok(HttpResponse::Ok().json(class)),
        None => Ok(HttpResponse::NotFound().json(json!({"error": {"code": "CLASS_NOT_FOUND", "message": "Class not found"}}))),
    }
}

#[utoipa::path(
    delete,
    path = "/api/classes/{id}",
    tag = "classes",
    security(("bearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Class ID")
    ),
    responses(
        (status = 204, description = "Class deleted successfully"),
        (status = 404, description = "Class not found"),
        (status = 403, description = "Forbidden - only teachers can delete their classes")
    )
)]
pub async fn delete_class(
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

    // Only teachers and principals can delete classes
    if !matches!(claims.role, UserRole::Teacher | UserRole::Principal) {
        return Err(crate::errors::ApiError::AuthorizationError);
    }

    // Teachers can only delete their own classes
    if matches!(claims.role, UserRole::Teacher) {
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

    let result = sqlx::query("DELETE FROM classes WHERE id = $1")
        .bind(class_id)
        .execute(pool.as_ref())
        .await
        .map_err(|e| {
            sentry::capture_error(&e);
            crate::errors::ApiError::from(e)
        })?;

    if result.rows_affected() == 0 {
        Ok(HttpResponse::NotFound().json(json!({"error": {"code": "CLASS_NOT_FOUND", "message": "Class not found"}})))
    } else {
        Ok(HttpResponse::NoContent().finish())
    }
}

#[utoipa::path(
    get,
    path = "/api/classes/{id}/teacher",
    tag = "classes",
    security(("bearerAuth" = [])),
    params(
        ("id" = Uuid, Path, description = "Class ID")
    ),
    responses(
        (status = 200, description = "Teacher details", body = User),
        (status = 404, description = "Class not found"),
        (status = 403, description = "Forbidden - insufficient permissions")
    )
)]
pub async fn get_class_teacher(
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

    // Check if user has access to this class
    let has_access = match claims.role {
        UserRole::Student => {
            // Students can see teacher details for classes they're enrolled in
            sqlx::query_scalar::<_, bool>(
                "SELECT EXISTS(SELECT 1 FROM class_students WHERE class_id = $1 AND student_id = $2)"
            )
            .bind(class_id)
            .bind(user_id)
            .fetch_one(pool.as_ref())
            .await
            .map_err(|e| {
                sentry::capture_error(&e);
                crate::errors::ApiError::from(e)
            })?
        }
        UserRole::Teacher => {
            // Teachers can see all teacher details
            true
        }
        UserRole::Principal => {
            // Principals can see all teacher details
            true
        }
    };

    if !has_access {
        return Err(crate::errors::ApiError::AuthorizationError);
    }

    let teacher = sqlx::query_as::<_, User>(
        "SELECT u.id, u.email, u.password_hash, u.role, u.is_superuser, u.public_key, u.recovery_key, 
         u.encrypted_private_key_blob, u.first_names, u.chosen_name, u.last_name, u.name_short, 
         u.birthday, u.ssn, u.learner_number, u.person_oid, u.avatar_url, u.phone, u.address, 
         u.enrollment_date, u.graduation_date, u.created_at, u.updated_at
         FROM users u 
         JOIN classes c ON u.id = c.teacher_id 
         WHERE c.id = $1"
    )
    .bind(class_id)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        sentry::capture_error(&e);
        crate::errors::ApiError::from(e)
    })?;

    match teacher {
        Some(teacher) => Ok(HttpResponse::Ok().json(teacher)),
        None => Ok(HttpResponse::NotFound().json(json!({"error": {"code": "CLASS_NOT_FOUND", "message": "Class not found"}}))),
    }
}
