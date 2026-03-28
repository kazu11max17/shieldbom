pub mod auth;
mod scans;

use axum::extract::{Request, State};
use axum::http::header::AUTHORIZATION;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use axum::Router;

use crate::errors::ApiError;
use crate::AppState;

pub fn router(state: AppState) -> Router {
    let public = Router::new()
        .route("/api/v1/auth/register", post(auth::register))
        .with_state(state.clone());

    let protected = Router::new()
        .route("/api/v1/scans", post(scans::create))
        .route("/api/v1/scans", get(scans::list))
        .route("/api/v1/scans/{id}", get(scans::get_by_id))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ))
        .with_state(state);

    Router::new()
        .route("/health", get(health))
        .merge(public)
        .merge(protected)
}

async fn health() -> &'static str {
    "ok"
}

/// Middleware: extract `Authorization: Bearer sk_live_xxx`, verify against DB,
/// inject account_id into request extensions.
async fn require_api_key(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let auth_header = req
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ApiError::Unauthorized("missing Authorization header".to_string()))?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or_else(|| ApiError::Unauthorized("invalid Authorization format".to_string()))?;

    let account_id = {
        let conn = state.db.lock().unwrap();
        crate::db::verify_api_key(&conn, token)
            .map_err(|e| ApiError::Internal(e.to_string()))?
            .ok_or_else(|| ApiError::Unauthorized("invalid or revoked API key".to_string()))?
    };

    req.extensions_mut().insert(AccountId(account_id));
    Ok(next.run(req).await)
}

/// Extracted from request extensions by handlers after auth middleware.
#[derive(Clone, Debug)]
pub struct AccountId(pub String);
