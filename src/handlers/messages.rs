use actix_web::{web, HttpRequest, HttpResponse, Result};
use serde_json::json;
use uuid::Uuid;
use log::error;
use sentry;

use crate::auth::extract_claims;
use crate::db::DbPool;
use crate::models::{SendMessageRequest, Thread, ThreadPreview, Message, MessageEncryptedKey, UserRole, PaginationQuery, MessagePaginationQuery, EncryptedKey};

#[utoipa::path(
    get,
    path = "/api/messages/threads",
    tag = "messages",
    security(("bearerAuth" = [])),
    params(
        ("limit" = Option<i32>, Query, description = "Maximum number of results"),
        ("offset" = Option<i32>, Query, description = "Offset for pagination")
    ),
    responses(
        (status = 200, description = "List of threads", body = [ThreadPreview])
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

#[utoipa::path(
    post,
    path = "/api/messages/threads",
    tag = "messages",
    security(("bearerAuth" = [])),
    request_body = SendMessageRequest,
    responses(
        (status = 201, description = "Message sent, thread created if needed")
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

    // Find existing thread with these exact participants
    let mut participants = message_req.participant_ids.clone();
    participants.sort();

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

    // Add participants to thread
    for participant_id in &message_req.participant_ids {
        sqlx::query("INSERT INTO thread_participants (thread_id, user_id) VALUES ($1, $2)")
            .bind(thread_id)
            .bind(participant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                error!("Database error: {}", e);
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

#[utoipa::path(
    get,
    path = "/api/messages/threads/{thread_id}",
    tag = "messages",
    security(("bearerAuth" = [])),
    params(
        ("thread_id" = String, Path, description = "Thread UUID"),
        ("limit" = Option<i32>, Query, description = "Maximum number of messages"),
        ("before" = Option<String>, Query, description = "Message ID to paginate before")
    ),
    responses(
        (status = 200, description = "Messages list", body = [Message])
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
    let is_participant: Option<()> = sqlx::query_scalar(
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

