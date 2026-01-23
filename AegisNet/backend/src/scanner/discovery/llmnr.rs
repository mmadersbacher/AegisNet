use tokio::net::UdpSocket;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::sync::mpsc;
use std::time::Duration;
use std::collections::HashSet;

pub struct LlmnrListener;

impl LlmnrListener {
    // Passive Listen on 5355
    pub async fn listen(timeout: Duration) -> Vec<String> {
        let (tx, mut rx) = mpsc::channel(100);
        
        tokio::spawn(async move {
            let _ = listen_llmnr(tx).await;
        });

        let mut devices = HashSet::new();
        let timeout_check = tokio::time::sleep(timeout);
        tokio::pin!(timeout_check);

        loop {
            tokio::select! {
                _ = &mut timeout_check => {
                    break;
                }
                Some(ip) = rx.recv() => {
                    devices.insert(ip);
                }
            }
        }
        
        devices.into_iter().collect()
    }
}

async fn listen_llmnr(tx: mpsc::Sender<String>) -> std::io::Result<()> {
    let port = 5355;
    let bind_addr = "224.0.0.252";
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).await?;
    
    // Join multicast
    if let Ok(addr) = bind_addr.parse::<Ipv4Addr>() {
        let _ = socket.join_multicast_v4(addr, Ipv4Addr::UNSPECIFIED);
    }
    
    let mut buf = [0u8; 1024];
    loop {
        if let Ok((_len, addr)) = socket.recv_from(&mut buf).await {
            let ip = addr.ip().to_string();
            if ip != "127.0.0.1" {
                let _ = tx.send(ip).await;
            }
        }
    }
}
