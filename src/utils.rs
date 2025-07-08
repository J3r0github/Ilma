use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::rngs::OsRng;
use log::error;
use sentry;

use crate::errors::{ApiError, ApiResult};

pub fn hash_password(password: &str) -> ApiResult<String> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

pub fn verify_password(password: &str, hash: &str) -> ApiResult<bool> {
    let parsed_hash = PasswordHash::new(hash)
        .map_err(|e| {
            error!("Failed to parse password hash: {:?}", e);
            sentry::capture_message(&e.to_string(), sentry::Level::Error);
            ApiError::InternalServerError
        })?;
    let argon2 = Argon2::default();
    Ok(argon2.verify_password(password.as_bytes(), &parsed_hash).is_ok())
}
