use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpStream;
use std::time::Duration;
use tokio::sync::mpsc;
use crate::scanner::Host;

pub struct TcpDiscovery;

impl TcpDiscovery {
    pub async fn scan_subnet(subnet: &str) -> Vec<String> {
        // Assume subnet is /24 for now, taking the base IP
        // Logic similar to previous "touch_host" but better structured
        let base_ip = subnet.split('/').next().unwrap_or("127.0.0.1");
        let parts: Vec<&str> = base_ip.split('.').collect();
        if parts.len() != 4 { return vec![]; }
        
        let prefix = format!("{}.{}.{}.", parts[0], parts[1], parts[2]);
        let (tx, mut rx) = mpsc::channel(255);

        for i in 1..255 {
            let target = format!("{}{}", prefix, i);
            let tx = tx.clone();
            tokio::spawn(async move {
                // Check common ports to trigger ARP and find services
                if is_port_open(&target, 80).await || // HTTP
                   is_port_open(&target, 443).await || // HTTPS
                   is_port_open(&target, 445).await || // SMB
                   is_port_open(&target, 22).await || // SSH
                   is_port_open(&target, 53).await || // DNS
                   is_port_open(&target, 3389).await || // RDP
                   is_port_open(&target, 62078).await || // iOS Sync
                   is_port_open(&target, 5000).await || // AirPlay Legacy
                   is_port_open(&target, 7000).await || // AirPlay
                   is_port_open(&target, 8080).await { // Alt HTTP
                    let _ = tx.send(target).await;
                }
            });
        }
        drop(tx);
        
        let mut alive = Vec::new();
        while let Some(ip) = rx.recv().await {
            alive.push(ip);
        }
        alive
    }
}

async fn is_port_open(ip: &str, port: u16) -> bool {
    // Connect with timeout - increased for Wi-Fi reliability
    let addr = format!("{}:{}", ip, port);
    if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
        return tokio::time::timeout(Duration::from_millis(150), TcpStream::connect(&socket_addr)).await.is_ok();
    }
    false
}
