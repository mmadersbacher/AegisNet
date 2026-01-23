use std::net::{IpAddr, Ipv4Addr, UdpSocket};
use std::str::FromStr;
use tokio::process::Command;
use std::collections::HashMap;
use serde::Serialize;
use tokio::sync::mpsc;

#[derive(Serialize, Clone, Debug)]
pub struct DiscoveredHost {
    pub ip: String,
    pub mac: String,
    pub vendor: String,
    pub hostname: String,
}

pub struct NetworkDiscovery;

impl NetworkDiscovery {
    pub fn detect_local_subnet() -> String {
        match UdpSocket::bind("0.0.0.0:0") {
            Ok(socket) => {
                if socket.connect("8.8.8.8:80").is_ok() {
                    if let Ok(addr) = socket.local_addr() {
                        if let IpAddr::V4(ip) = addr.ip() {
                            let octets = ip.octets();
                            return format!("{}.{}.{}.0/24", octets[0], octets[1], octets[2]);
                        }
                    }
                }
            }
            Err(_) => {}
        }
        "127.0.0.1/24".to_string()
    }

    pub async fn scan_subnet(cidr: &str) -> Vec<DiscoveredHost> {
        let parts: Vec<&str> = cidr.split('/').collect();
        let ip_str = if parts.is_empty() { "127.0.0.1" } else { parts[0] };
        
        let base_ip = Ipv4Addr::from_str(ip_str).unwrap_or(Ipv4Addr::new(127,0,0,1));
        let octets = base_ip.octets();
        let subnet_prefix = format!("{}.{}.{}.", octets[0], octets[1], octets[2]);

        let (tx, mut rx) = mpsc::channel(255);
        
        for i in 1..255 {
            let target_ip = IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], i));
            let tx_clone = tx.clone();
            tokio::spawn(async move {
                touch_host(target_ip).await;
                let _ = tx_clone.send(());
            });
        }
        drop(tx);
        while rx.recv().await.is_some() {}

        let arp_entries = get_arp_table().await;
        
        let mut results = Vec::new();
        for (ip, mac) in arp_entries {
            if ip.starts_with(&subnet_prefix) {
                let vendor = lookup_vendor(&mac);
                let hostname = if vendor.contains("Apple") { "Apple Device".to_string() } 
                               else if vendor.contains("Espressif") { "Smart Home IoT".to_string() }
                               else { "Network Device".to_string() };

                results.push(DiscoveredHost { ip, mac, vendor, hostname });
            }
        }
        
        results.sort_by(|a, b| {
             let a_last = a.ip.split('.').last().unwrap_or("0").parse::<u8>().unwrap_or(0);
             let b_last = b.ip.split('.').last().unwrap_or("0").parse::<u8>().unwrap_or(0);
             a_last.cmp(&b_last)
        });

        results
    }
}

async fn touch_host(ip: IpAddr) {
    use tokio::net::TcpStream;
    use std::time::Duration;
    let _ = tokio::time::timeout(Duration::from_millis(50), TcpStream::connect(&std::net::SocketAddr::new(ip, 80))).await;
    let _ = tokio::time::timeout(Duration::from_millis(50), TcpStream::connect(&std::net::SocketAddr::new(ip, 445))).await;
}

async fn get_arp_table() -> HashMap<String, String> {
    let output = match Command::new("arp").arg("-a").output().await {
        Ok(o) => o,
        Err(_) => return HashMap::new(),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut map = HashMap::new();

    for line in stdout.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 3 {
             let mut ip = String::new();
             let mut mac = String::new();
             for part in &parts {
                 if part.contains('.') && part.chars().any(|c| c.is_numeric()) {
                     let clean = part.replace("(", "").replace(")", "");
                     if clean.split('.').count() == 4 { ip = clean; }
                 } else if (part.contains('-') || part.contains(':')) && part.len() == 17 {
                     mac = part.replace('-', ":").to_uppercase();
                 }
             }
             if !ip.is_empty() && !mac.is_empty() && !ip.starts_with("224.") && !ip.starts_with("244.") && !ip.starts_with("255.") {
                 map.insert(ip, mac);
             }
        }
    }
    map
}

fn lookup_vendor(mac: &str) -> String {
    let clean = mac.replace(":", "").replace("-", "").to_uppercase();
    if clean.len() < 6 { return "Unknown".to_string(); }
    let prefix = &clean[0..6];

    match prefix {
        "BC5C4C" | "F01898" | "7C6DF8" | "FE5F01" => "Apple, Inc.".to_string(),
        "240AC4" | "ECFABC" | "2462AB" => "Espressif (IoT)".to_string(),
        "B827EB" | "DCA632" | "E45F01" => "Raspberry Pi".to_string(),
        "7483C2" | "F09FC2" | "00156D" => "Ubiquiti Networks".to_string(),
        "001478" | "0016D4" | "50C7BF" => "TP-Link".to_string(),
        "000C29" | "005056" => "VMware".to_string(),
        "00155D" => "Microsoft Hyper-V".to_string(),
        "00A0C9" | "0002B3" => "Intel".to_string(),
        _ => "Unknown Vendor".to_string(),
    }
}
