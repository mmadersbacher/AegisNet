use axum::{
    Json,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use crate::services::scanner::Scanner;

#[derive(Deserialize)]
pub struct ScanRequest {
    pub target: String,
    pub start_port: u16,
    pub end_port: u16,
}

use crate::scanner::{self, Host};
use crate::scanner::core::ScannerCore;
use crate::services::discovery;

#[derive(Serialize)]
pub struct ScanResponse {
    pub target: String,
    pub status: String,
    pub hosts: Vec<Host>,
}

pub async fn start_scan(
    Json(payload): Json<ScanRequest>,
) -> impl IntoResponse {
    let target = if payload.target == "auto" {
        discovery::NetworkDiscovery::detect_local_subnet()
    } else {
        payload.target.clone()
    };

    println!("Starting Next-Gen Scan on: {}", target);

    // Call the new Engine
    let hosts = ScannerCore::scan_network(&target).await;

    Json(ScanResponse { 
        target, 
        status: "Completed".into(),
        hosts 
    })
}
