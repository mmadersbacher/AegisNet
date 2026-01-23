use tokio::net::UdpSocket;
use std::time::Duration;
use tokio::sync::mpsc;
use std::net::SocketAddr;
use std::sync::Arc;

pub struct UdpScanner;

impl UdpScanner {
    // Scan subnet for DNS (53) and NTP (123)
    pub async fn scan_subnet(subnet: &str) -> Vec<String> {
        let base_ip = subnet.split('/').next().unwrap_or("127.0.0.1");
        let parts: Vec<&str> = base_ip.split('.').collect();
        if parts.len() != 4 { return vec![]; }
        
        let prefix = format!("{}.{}.{}.", parts[0], parts[1], parts[2]);
        let (tx, mut rx) = mpsc::channel(255);

        // Bind ephemeral
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => Arc::new(s),
            Err(_) => return vec![],
        };

        // 1. DNS Query Packet (Standard Query for "google.com")
        // Header: ID=0x1234, Flags=0x0100 (Recursive), QD=1, AN=0...
        // QName: \x06google\x03com\x00, QType=A, QClass=IN
        let dns_packet = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 
            0x00, 0x01, 0x00, 0x01
        ];

        // 2. NTP Client Request (Mode 3, Version 3)
        // LI=0, VN=3, Mode=3 -> 0x1B
        let mut ntp_packet = [0u8; 48];
        ntp_packet[0] = 0x1B;

        // Receiver Task
        let socket_recv = socket.clone();
        let tx_res = tx.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = tokio::time::timeout(Duration::from_secs(4), async {
                loop {
                    if let Ok((_len, addr)) = socket_recv.recv_from(&mut buf).await {
                         let _ = tx_res.send(addr.ip().to_string()).await;
                    }
                }
            }).await;
        });

        // Sender Loop
        for i in 1..255 {
            let target_ip = format!("{}{}", prefix, i);
            
            let socket_send = socket.clone();
            
            // Probe DNS (53)
            if let Ok(addr) = format!("{}:53", target_ip).parse::<SocketAddr>() {
                let _ = socket_send.send_to(&dns_packet, addr).await;
            }
            
            // Probe NTP (123)
            if let Ok(addr) = format!("{}:123", target_ip).parse::<SocketAddr>() {
                let _ = socket_send.send_to(&ntp_packet, addr).await;
            }

            // Pace it slightly
            if i % 10 == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        
        drop(tx);
        
        let mut results = Vec::new();
        while let Some(ip) = rx.recv().await {
            results.push(ip);
        }
        results
    }
}
