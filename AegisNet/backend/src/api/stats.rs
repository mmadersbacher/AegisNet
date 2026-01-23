use axum::{
    Json,
    extract::State,
    response::IntoResponse,
    http::StatusCode,
};
use sea_orm::*;
use serde::Serialize;
use crate::entities::log;

#[derive(Serialize)]
pub struct StatsResponse {
    pub total_logs: u64,
    pub threat_level: String,
    pub active_agents: u32,
    pub alerts_24h: u64,
}

pub async fn get_stats(
    State(db): State<DatabaseConnection>,
) -> impl IntoResponse {
    // Count total logs
    let total_logs = log::Entity::find().count(&db).await.unwrap_or(0);
    
    // Count alerts (WARN/ERROR)
    let alerts = log::Entity::find()
        .filter(
            Condition::any()
                .add(log::Column::Level.eq("ERROR"))
                .add(log::Column::Level.eq("WARN"))
        )
        .count(&db)
        .await
        .unwrap_or(0);

    let threat_level = if alerts > 50 { "HIGH" } else if alerts > 10 { "ELEVATED" } else { "LOW" };

    Json(StatsResponse {
        total_logs,
        threat_level: threat_level.to_string(),
        active_agents: 1, // Mock for now or count distinct sources
        alerts_24h: alerts, 
    })
}
