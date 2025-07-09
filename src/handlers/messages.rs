use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use uuid::Uuid;
use log::error;
use sentry;

use crate::auth::extract_claims;
use crate::db::DbPool;
use crate::models::{SendMessageRequest, ThreadPreview, Message, MessageEncryptedKey, PaginationQuery, MessagePaginationQuery, EncryptedKey, ErrorResponse};

/// List all message threads for the authenticated user
/// 
/// Returns a paginated list of thread previews showing the most recent message
/// from each thread that the user participates in.
#[utoipa::path(
    get,
    path = "/api/messages/threads",
    tag = "messages",
    security(("bearerAuth" = [])),
    params(
        ("limit" = Option<i32>, Query, description = "Maximum number of results (default: 20)"),
        ("offset" = Option<i32>, Query, description = "Offset for pagination (default: 0)")
    ),
    responses(
        (status = 200, description = "List of thread previews for the authenticated user", body = [ThreadPreview]),
        (status = 401, description = "Authentication required", body = ErrorResponse),
        (status = 400, description = "Invalid user ID format", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn list_threads(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    query: web::Query<PaginationQuery>,
) -> Result<HttpResponse, actix_web::Error> {
    let claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    let user_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            actix_web::error::ErrorBadRequest("Invalid user ID format")
        })?;
    let limit = query.limit.unwrap_or(20);
    let offset = query.offset.unwrap_or(0);

    let thread_previews: Vec<ThreadPreview> = sqlx::query_as(
        "SELECT DISTINCT 
            t.id as thread_id,
            SUBSTRING(m.ciphertext, 1, 100) as last_message_preview,
            m.sent_at as last_message_at
         FROM threads t
         JOIN thread_participants tp ON t.id = tp.thread_id
         LEFT JOIN messages m ON t.id = m.thread_id
         WHERE tp.user_id = $1
         AND m.sent_at = (
             SELECT MAX(sent_at) 
             FROM messages m2 
             WHERE m2.thread_id = t.id
         )
         ORDER BY m.sent_at DESC
         LIMIT $2 OFFSET $3"
    )
    .bind(user_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        sentry::capture_error(&e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    Ok(HttpResponse::Ok().json(thread_previews))
}

/// Send an encrypted message to specified participants
/// 
/// Creates a new thread with the specified participants (including the sender)
/// and sends an encrypted message. Each recipient gets their own encrypted key
/// to decrypt the message content.
#[utoipa::path(
    post,
    path = "/api/messages/threads",
    tag = "messages",
    security(("bearerAuth" = [])),
    request_body(content = SendMessageRequest, description = "Message data including participants, encrypted content, and keys"),
    responses(
        (status = 201, description = "Message sent successfully, thread created if needed", body = String, example = json!({"message": "Message sent successfully", "thread_id": "550e8400-e29b-41d4-a716-446655440000", "message_id": "550e8400-e29b-41d4-a716-446655440001"})),
        (status = 400, description = "Invalid request data or non-existent participant", body = ErrorResponse),
        (status = 401, description = "Authentication required", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn send_message(
    req: HttpRequest,
    pool: web::Data<DbPool>,
    message_req: web::Json<SendMessageRequest>,
) -> Result<HttpResponse, actix_web::Error> {
    let claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    let sender_id = Uuid::parse_str(&claims.sub)
        .map_err(|e| {
            sentry::capture_error(&e);
            actix_web::error::ErrorBadRequest("Invalid user ID format")
        })?;

    // Start a transaction
    let mut tx = pool.begin().await.map_err(|e| {
        error!("Transaction error: {}", e);
        sentry::capture_error(&e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    // Validate that all participant IDs exist in the users table
    let mut all_participants = message_req.participant_ids.clone();
    // Ensure sender is included in participants
    if !all_participants.contains(&sender_id) {
        all_participants.push(sender_id);
    }
    
    for participant_id in &all_participants {
        let user_exists: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM users WHERE id = $1"
        )
        .bind(participant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            error!("Database error checking user existence: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;
        
        if user_exists.is_none() {
            return Ok(HttpResponse::BadRequest().json(json!({
                "error": format!("User with ID {} does not exist", participant_id)
            })));
        }
    }

    // For simplicity, we'll create a new thread for each message
    // In a real implementation, you'd want to find existing threads with the same participants
    let thread_id = Uuid::new_v4();

    // Create new thread
    sqlx::query("INSERT INTO threads (id) VALUES ($1)")
        .bind(thread_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            error!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?;

    // Add participants to thread (including sender)
    for participant_id in &all_participants {
        sqlx::query("INSERT INTO thread_participants (thread_id, user_id) VALUES ($1, $2)")
            .bind(thread_id)
            .bind(participant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("Database error adding participant {}: {}", participant_id, e);
                actix_web::error::ErrorInternalServerError("Database error")
            })?;
    }

    let message_id = Uuid::new_v4();

    // Create message
    sqlx::query(
        "INSERT INTO messages (id, thread_id, sender_id, ciphertext) 
         VALUES ($1, $2, $3, $4)"
    )
    .bind(message_id)
    .bind(thread_id)
    .bind(sender_id)
    .bind(&message_req.ciphertext)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    // Store encrypted keys for each recipient
    for encrypted_key in &message_req.encrypted_keys {
        sqlx::query(
            "INSERT INTO message_encrypted_keys (message_id, recipient_id, encrypted_key) 
             VALUES ($1, $2, $3)"
        )
        .bind(message_id)
        .bind(encrypted_key.recipient_id)
        .bind(&encrypted_key.encrypted_key)
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

    Ok(HttpResponse::Created().json(json!({
        "message": "Message sent successfully",
        "thread_id": thread_id,
        "message_id": message_id
    })))
}

/// Get messages from a specific thread
/// 
/// Retrieves encrypted messages from a thread that the user participates in.
/// Messages are returned with encrypted keys for each recipient. Supports
/// cursor-based pagination using the 'before' parameter.
#[utoipa::path(
    get,
    path = "/api/messages/threads/{thread_id}",
    tag = "messages",
    security(("bearerAuth" = [])),
    params(
        ("thread_id" = Uuid, Path, description = "Thread UUID to retrieve messages from"),
        ("limit" = Option<i32>, Query, description = "Maximum number of messages to retrieve (default: 20)"),
        ("before" = Option<String>, Query, description = "Message ID to paginate before (for cursor-based pagination)")
    ),
    responses(
        (status = 200, description = "Messages from the specified thread with encrypted keys", body = [Message]),
        (status = 400, description = "Invalid thread ID or message ID format", body = ErrorResponse),
        (status = 401, description = "Authentication required", body = ErrorResponse),
        (status = 403, description = "User is not a participant in this thread", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse)
    )
)]
pub async fn get_thread_messages(
    req: HttpRequest,
    path: web::Path<Uuid>,
    pool: web::Data<DbPool>,
    query: web::Query<MessagePaginationQuery>,
) -> Result<HttpResponse, actix_web::Error> {
    let claims = extract_claims(&req)
        .ok_or_else(|| actix_web::error::ErrorUnauthorized("Authentication required"))?;

    let user_id = Uuid::parse_str(&claims.sub).unwrap();
    let thread_id = path.into_inner();
    let limit = query.limit.unwrap_or(20);

    // Check if user is participant in this thread
    let is_participant: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM thread_participants WHERE thread_id = $1 AND user_id = $2"
    )
    .bind(thread_id)
    .bind(user_id)
    .fetch_optional(pool.as_ref())
    .await
    .map_err(|e| {
        error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    if is_participant.is_none() {
        return Ok(HttpResponse::Forbidden().json(json!({"error": "You are not a participant in this thread"})));
    }

    // Get messages
    let mut messages: Vec<Message> = if let Some(before_id) = &query.before {
        let before_uuid = Uuid::parse_str(before_id).map_err(|_| {
            actix_web::error::ErrorBadRequest("Invalid message ID format")
        })?;
        
        sqlx::query_as(
            "SELECT id, thread_id, sender_id, sent_at, ciphertext 
             FROM messages 
             WHERE thread_id = $1 AND sent_at < (
                 SELECT sent_at FROM messages WHERE id = $2
             )
             ORDER BY sent_at DESC 
             LIMIT $3"
        )
        .bind(thread_id)
        .bind(before_uuid)
        .bind(limit)
        .fetch_all(pool.as_ref())
        .await
    } else {
        sqlx::query_as(
            "SELECT id, thread_id, sender_id, sent_at, ciphertext 
             FROM messages 
             WHERE thread_id = $1 
             ORDER BY sent_at DESC 
             LIMIT $2"
        )
        .bind(thread_id)
        .bind(limit)
        .fetch_all(pool.as_ref())
        .await
    }
    .map_err(|e| {
        error!("Database error: {}", e);
        actix_web::error::ErrorInternalServerError("Database error")
    })?;

    // Get encrypted keys for each message
    for message in &mut messages {
        let encrypted_keys: Vec<EncryptedKey> = sqlx::query_as::<_, MessageEncryptedKey>(
            "SELECT message_id, recipient_id, encrypted_key 
             FROM message_encrypted_keys 
             WHERE message_id = $1"
        )
        .bind(message.id)
        .fetch_all(pool.as_ref())
        .await
        .map_err(|e| {
            error!("Database error: {}", e);
            actix_web::error::ErrorInternalServerError("Database error")
        })?
        .into_iter()
        .map(|key| EncryptedKey {
            recipient_id: key.recipient_id,
            encrypted_key: key.encrypted_key,
        })
        .collect();

        message.encrypted_keys = encrypted_keys;
    }

    Ok(HttpResponse::Ok().json(messages))
}

