use axum::{
    extract::State,
    Json,
};
use serde_json::{Value, json};
use std::sync::Arc;
use crate::scanner::traffic::store::TrafficStore;

pub async fn get_traffic(State(store): State<Arc<TrafficStore>>) -> Json<Value> {
    // Collect Flows
    let flows: Vec<_> = store.flows.iter().map(|r| r.value().clone()).collect();
    
    // Collect Device Stats
    let stats: Vec<_> = store.device_stats.iter().map(|r| r.value().clone()).collect();

    Json(json!({
        "flow_count": flows.len(),
        "flows": flows,
        "device_stats": stats
    }))
}
