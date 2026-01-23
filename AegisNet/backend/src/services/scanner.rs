use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    pub ip: String,
    pub open_ports: Vec<u16>,
    pub status: String,
}

pub struct Scanner {
    pub target: IpAddr,
    pub start_port: u16,
    pub end_port: u16,
}

impl Scanner {
    pub fn new(target: IpAddr, start_port: u16, end_port: u16) -> Self {
        Self {
            target,
            start_port,
            end_port,
        }
    }

    pub async fn run(&self) -> ScanResult {
        let (tx, mut rx) = mpsc::channel(100);
        let mut open_ports = Vec::new();

        // Spawn tasks for each port
        for port in self.start_port..=self.end_port {
            let target = self.target;
            let tx = tx.clone();
            
            tokio::spawn(async move {
                if scan_port(target, port).await {
                    let _ = tx.send(port).await;
                }
            });
        }
        
        // Drop original tx so rx knows when to stop
        drop(tx);

        while let Some(port) = rx.recv().await {
            open_ports.push(port);
        }
        open_ports.sort();

        ScanResult {
            ip: self.target.to_string(),
            open_ports,
            status: "Completed".to_string(),
        }
    }
}

async fn scan_port(ip: IpAddr, port: u16) -> bool {
    let addr = SocketAddr::new(ip, port);
    // Short timeout for speed
    let timeout = Duration::from_millis(500); 
    
    match tokio::time::timeout(timeout, TcpStream::connect(&addr)).await {
        Ok(Ok(_)) => true,
        _ => false,
    }
}
