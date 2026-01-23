use axum::{
    Json,
    extract::State,
    response::IntoResponse,
    http::StatusCode,
};
use sea_orm::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::entities::log;
use chrono::Utc;

#[derive(Deserialize)]
pub struct CreateLogRequest {
    pub source: String,
    pub level: String,
    pub message: String,
    pub raw_content: String,
    pub metadata: Option<serde_json::Value>,
}

pub async fn ingest_log(
    State(db): State<DatabaseConnection>,
    Json(payload): Json<CreateLogRequest>,
) -> impl IntoResponse {
    let new_log = log::ActiveModel {
        source: Set(payload.source),
        level: Set(payload.level),
        message: Set(payload.message),
        raw_content: Set(payload.raw_content),
        event_time: Set(Utc::now().naive_utc()), // Simplified for now
        received_at: Set(Utc::now().naive_utc()),
        metadata: Set(payload.metadata.map(|v| v.to_string())),
        ..Default::default()
    };

    match log::Entity::insert(new_log).exec(&db).await {
        Ok(res) => (StatusCode::CREATED, Json(json!({ "id": res.last_insert_id }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to insert log: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to ingest log").into_response()
        }
    }
}
