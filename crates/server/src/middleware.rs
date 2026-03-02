use axum::{
    Json,
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::{IntoResponse, Response},
};
use fishnet_types::auth::ErrorResponse;

use crate::state::AppState;

pub async fn require_auth(State(state): State<AppState>, request: Request, next: Next) -> Response {
    let auth_header = request
        .headers()
        .get("authorization")
        .and_then(|v| v.to_str().ok());

    let token = match auth_header {
        Some(h) if h.starts_with("Bearer ") => &h[7..],
        _ => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "missing or invalid authorization header".to_string(),
                    retry_after_seconds: None,
                }),
            )
                .into_response();
        }
    };

    if !state.session_store.validate(token).await {
        return (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "invalid or expired session token".to_string(),
                retry_after_seconds: None,
            }),
        )
            .into_response();
    }

    next.run(request).await
}
