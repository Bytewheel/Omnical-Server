use axum::response::{IntoResponse, Response};
use http::StatusCode;
use rustical_store::Error as StoreError;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error(transparent)]
    Store(#[from] StoreError),

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Forbidden: {0}")]
    Forbidden(String),

    #[error("Bad request: {0}")]
    BadRequest(String),
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            Self::Store(err) => {
                // Omnical §17.9.2: privilege invariants are authorization
                // failures, not server errors.
                if matches!(err, StoreError::LastAdmin | StoreError::OwnerNotDemotable) {
                    (StatusCode::FORBIDDEN, err.to_string())
                } else {
                    tracing::error!(%err, "store error");
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Internal server error".to_owned(),
                    )
                }
            }
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            Self::Forbidden(msg) => (StatusCode::FORBIDDEN, msg.clone()),
            Self::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
        };
        (status, message).into_response()
    }
}
