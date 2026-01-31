use axum::{
    routing::{get, post},
    Router,
    Json,
};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tower_http::cors::CorsLayer;

mod db;
mod entities;
mod api;
mod services;
mod scanner;

use axum::extract::FromRef;
use scanner::traffic::store::TrafficStore;
use std::sync::Arc;
use sea_orm::DatabaseConnection;

#[derive(Clone)]
struct AppState {
    db: DatabaseConnection,
    traffic: Arc<TrafficStore>,
}

impl FromRef<AppState> for DatabaseConnection {
    fn from_ref(state: &AppState) -> Self {
        state.db.clone()
    }
}

impl FromRef<AppState> for Arc<TrafficStore> {
    fn from_ref(state: &AppState) -> Self {
        state.traffic.clone()
    }
}

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    // Load env vars
    dotenvy::dotenv().ok();

    // Initialize OUI Database (Download if needed)
    scanner::fingerprint::oui_live::OuiLive::init().await;

    // Start Traffic Analysis (Packet Sniffer)
    let traffic_analyzer = scanner::traffic::TrafficAnalyzer::new();
    traffic_analyzer.start().await;

    // Connect to DB
    let db = match db::connect().await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("Failed to connect to database: {}", e);
            std::process::exit(1);
        }
    };
    
    let state = AppState {
        db,
        traffic: traffic_analyzer.get_store(),
    };

    // CORS Layer
    let cors = CorsLayer::permissive();

    // Build application with routes
    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        .route("/api/v1/logs", post(api::ingest::ingest_log).get(api::ingest::list_logs))
        .route("/api/v1/scan", post(api::scan::start_scan))
        .route("/api/v1/stats", get(api::stats::get_stats))
        .route("/api/v1/traffic", get(api::traffic::get_traffic)) // New Endpoint
        .with_state(state)
        .layer(cors);

    // Run app
    let addr = SocketAddr::from(([0, 0, 0, 0], 8000));
    tracing::info!("listening on {}", addr);
    
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn root() -> Json<Value> {
    Json(json!({
        "system": "AegisNet",
        "status": "operational",
        "modules": {
            "siem": "active", 
            "scanner": "standing_by",
            "detection": "active"
        }
    }))
}

async fn health_check() -> Json<Value> {
    Json(json!({ "status": "healthy" }))
}
