use axum::{
    Json,
    extract::{State, Query},
    response::IntoResponse,
    http::StatusCode,
};
use sea_orm::*;
use serde::{Deserialize, Serialize};
use serde_json::json;
use crate::entities::log;
use crate::services::normalization;
use chrono::Utc;

#[derive(Deserialize)]
pub struct CreateLogRequest {
    pub source: String,
    pub raw_content: String,
    // Optional overrides, otherwise parsed
    pub level: Option<String>,
    pub message: Option<String>,
    pub metadata: Option<serde_json::Value>,
}

pub async fn ingest_log(
    State(db): State<DatabaseConnection>,
    Json(payload): Json<CreateLogRequest>,
) -> impl IntoResponse {
    let normalized = normalization::normalize_log(&payload.raw_content, &payload.source);
    
    // Run Detection
    let detector = crate::services::detection::DetectionEngine::new();
    if let Some(alert_msg) = detector.analyze(&normalized) {
        tracing::warn!("{}", alert_msg);
        // TODO: Store alert in DB
    }

    // Prefer payload overrides if present
    let final_level = payload.level.unwrap_or(normalized.level);
    let final_message = payload.message.unwrap_or(normalized.message);
    let final_metadata = payload.metadata.or(normalized.metadata);

    let new_log = log::ActiveModel {
        source: Set(normalized.source),
        level: Set(final_level),
        message: Set(final_message),
        raw_content: Set(payload.raw_content),
        event_time: Set(normalized.event_time.naive_utc()), 
        received_at: Set(Utc::now().naive_utc()),
        metadata: Set(final_metadata.map(|v| v.to_string())),
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

#[derive(Deserialize)]
pub struct ListLogsParams {
    pub page: Option<u64>,
    pub limit: Option<u64>,
}

#[derive(Serialize)]
pub struct LogResponse {
    pub id: i32,
    pub source: String,
    pub level: String,
    pub message: String,
    pub event_time: String,
}

pub async fn list_logs(
    State(db): State<DatabaseConnection>,
    Query(params): Query<ListLogsParams>,
) -> impl IntoResponse {
    let page = params.page.unwrap_or(1);
    let limit = params.limit.unwrap_or(50);
    
    // Pagination
    let paginator = log::Entity::find()
        .order_by_desc(log::Column::EventTime)
        .paginate(&db, limit);
        
    match paginator.fetch_page(page - 1).await {
        Ok(logs) => {
            let res: Vec<LogResponse> = logs.into_iter().map(|l| LogResponse {
                id: l.id,
                source: l.source,
                level: l.level,
                message: l.message,
                event_time: l.event_time.to_string(),
            }).collect();
            Json(res).into_response()
        },
        Err(e) => {
            tracing::error!("Failed to fetch logs: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Failed to fetch logs").into_response()
        }
    }
}
