use axum::extract::State;
use axum::Json;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::db;
use crate::errors::ApiError;
use crate::AppState;

#[derive(Deserialize)]
pub struct RegisterRequest {
    pub email: String,
}

#[derive(Serialize)]
pub struct RegisterResponse {
    pub account_id: String,
    pub email: String,
    pub api_key: String,
    pub key_prefix: String,
    pub plan: String,
}

pub async fn register(
    State(state): State<AppState>,
    Json(req): Json<RegisterRequest>,
) -> Result<Json<RegisterResponse>, ApiError> {
    if req.email.is_empty() || !req.email.contains('@') {
        return Err(ApiError::BadRequest("invalid email".to_string()));
    }

    let account_id = format!("acc_{}", Uuid::new_v4());
    let now = Utc::now().to_rfc3339();
    let (raw_key, prefix, key_hash) = db::generate_api_key();
    let key_id = format!("key_{}", Uuid::new_v4());

    let conn = state.db.lock().unwrap();

    // Check if email already exists
    let exists: bool = conn
        .query_row(
            "SELECT COUNT(*) > 0 FROM accounts WHERE email = ?1",
            rusqlite::params![req.email],
            |row| row.get(0),
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;

    if exists {
        return Err(ApiError::BadRequest("email already registered".to_string()));
    }

    conn.execute(
        "INSERT INTO accounts (id, email, plan, created_at) VALUES (?1, ?2, 'free', ?3)",
        rusqlite::params![account_id, req.email, now],
    )?;

    conn.execute(
        "INSERT INTO api_keys (id, account_id, key_hash, key_prefix, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
        rusqlite::params![key_id, account_id, key_hash, prefix, now],
    )?;

    Ok(Json(RegisterResponse {
        account_id,
        email: req.email,
        api_key: raw_key,
        key_prefix: prefix,
        plan: "free".to_string(),
    }))
}
