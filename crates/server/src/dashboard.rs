use axum::{
    body::Body,
    http::{StatusCode, Uri, header},
    response::{IntoResponse, Response},
};
use rust_embed::Embed;

#[derive(Embed)]
#[folder = "../../dashboard/dist"]
struct Assets;

pub async fn static_handler(uri: Uri) -> Response {
    let path = uri.path().trim_start_matches('/');

    // Try the exact path first
    if let Some(file) = Assets::get(path) {
        return file_response(path, &file);
    }

    // SPA fallback: serve index.html for any non-file path
    match Assets::get("index.html") {
        Some(file) => file_response("index.html", &file),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

fn file_response(path: &str, file: &rust_embed::EmbeddedFile) -> Response {
    let mime = mime_guess::from_path(path).first_or_octet_stream();

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, mime.as_ref().to_string()),
            (
                header::CACHE_CONTROL,
                if path.contains("assets/") {
                    "public, max-age=31536000, immutable".to_string()
                } else {
                    "no-cache".to_string()
                },
            ),
        ],
        Body::from(file.data.clone()),
    )
        .into_response()
}
