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

#[tokio::main]
async fn main() {
    // Initialize tracing
    tracing_subscriber::fmt::init();
    
    // Load env vars
    dotenvy::dotenv().ok();

    // Connect to DB
    let _db = match db::connect().await {
        Ok(conn) => conn,
        Err(e) => {
            tracing::error!("Failed to connect to database: {}", e);
            std::process::exit(1);
        }
    };

    // CORS Layer
    let cors = CorsLayer::permissive();

    // Build application with routes
    let app = Router::new()
        .route("/", get(root))
        .route("/health", get(health_check))
        .route("/api/v1/logs", post(api::ingest::ingest_log))
        .with_state(_db)
        .layer(cors);

    // Run app
    let addr = SocketAddr::from(([127, 0, 0, 1], 8000));
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
