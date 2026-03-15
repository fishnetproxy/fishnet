use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use fishnet_types::auth::*;
use zeroize::Zeroizing;

use crate::state::AppState;

pub async fn status(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let initialized = state.password_store.is_initialized().unwrap_or(false);

    let authenticated =
        if let Some(auth_header) = headers.get("authorization").and_then(|v| v.to_str().ok()) {
            if let Some(token) = auth_header.strip_prefix("Bearer ") {
                state.session_store.validate(token).await
            } else {
                false
            }
        } else {
            false
        };

    Json(AuthStatusResponse {
        initialized,
        authenticated,
    })
}

pub async fn setup(State(state): State<AppState>, Json(req): Json<SetupRequest>) -> Response {
    let password = Zeroizing::new(req.password);
    let confirm = Zeroizing::new(req.confirm);

    match state.password_store.is_initialized() {
        Ok(true) => {
            return (
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "password already configured".to_string(),
                    retry_after_seconds: None,
                }),
            )
                .into_response();
        }
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse {
                    error: format!("internal error: {e}"),
                    retry_after_seconds: None,
                }),
            )
                .into_response();
        }
        _ => {}
    }

    if password.as_str() != confirm.as_str() {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "passwords do not match".to_string(),
                retry_after_seconds: None,
            }),
        )
            .into_response();
    }

    if password.len() < 8 {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "password must be at least 8 characters".to_string(),
                retry_after_seconds: None,
            }),
        )
            .into_response();
    }

    match state.password_store.setup(password.as_str()) {
        Ok(()) => Json(SetupResponse {
            success: true,
            message: "password configured successfully".to_string(),
        })
        .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("failed to setup password: {e}"),
                retry_after_seconds: None,
            }),
        )
            .into_response(),
    }
}

pub async fn login(State(state): State<AppState>, Json(req): Json<LoginRequest>) -> Response {
    let password = Zeroizing::new(req.password);

    if let Err(retry_after) = state.rate_limiter.check_rate_limit().await {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: "too many failed login attempts".to_string(),
                retry_after_seconds: Some(retry_after),
            }),
        )
            .into_response();
    }

    state.rate_limiter.progressive_delay().await;

    match state.password_store.verify(password.as_str()) {
        Ok(true) => {
            state.rate_limiter.reset().await;
            let session = state.session_store.create().await;
            Json(LoginResponse {
                token: session.token,
                expires_at: session.expires_at,
            })
            .into_response()
        }
        Ok(false) => {
            state.rate_limiter.record_failure().await;
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "invalid password".to_string(),
                    retry_after_seconds: None,
                }),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse {
                error: format!("internal error: {e}"),
                retry_after_seconds: None,
            }),
        )
            .into_response(),
    }
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let token = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
        .unwrap_or("");

    state.session_store.remove(token).await;

    Json(LogoutResponse { success: true })
}
