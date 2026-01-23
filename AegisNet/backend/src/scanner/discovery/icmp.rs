use tokio::process::Command;
use std::time::Duration;
use tokio::sync::mpsc;

pub struct IcmpScanner;

impl IcmpScanner {
    // Aggressive ping sweep of the subnet
    pub async fn scan_subnet(subnet: &str) -> Vec<String> {
        let base_ip = subnet.split('/').next().unwrap_or("127.0.0.1");
        let parts: Vec<&str> = base_ip.split('.').collect();
        if parts.len() != 4 { return vec![]; }
        
        let prefix = format!("{}.{}.{}.", parts[0], parts[1], parts[2]);
        let (tx, mut rx) = mpsc::channel(255);

        // Ping every host 1-254
        for i in 1..255 {
            let target = format!("{}{}", prefix, i);
            let tx = tx.clone();
            tokio::spawn(async move {
                if ping_host(&target).await {
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

async fn ping_host(ip: &str) -> bool {
    // Windows ping: -n 1 (count), -w 200 (timeout in ms)
    let output = Command::new("ping")
        .args(&["-n", "1", "-w", "200", ip])
        .output()
        .await;

    match output {
        Ok(out) => out.status.success(),
        Err(_) => false,
    }
}
