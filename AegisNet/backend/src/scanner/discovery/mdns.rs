use std::net::{Ipv4Addr, SocketAddr};
use socket2::{Socket, Domain, Type, Protocol};
use tokio::net::UdpSocket;
use std::time::Duration;
use std::collections::HashMap;
use tokio::sync::mpsc;
use dns_lookup::lookup_addr;

#[derive(Debug, Clone)]
pub struct MdnsInfo {
    pub ip: String,
    pub hostname: Option<String>,
    pub model: Option<String>, // extracted from TXT or PTR
    pub device_role: Option<String>,
}

pub struct MdnsScanner;

impl MdnsScanner {
    pub async fn scan(timeout: Duration) -> HashMap<String, MdnsInfo> {
        let (tx, mut rx) = mpsc::channel(100);
        
        // Listener Task
        let tx_listener = tx.clone();
        tokio::spawn(async move {
            let _ = listen_mdns(tx_listener).await;
        });

        // Broadcaster Task (Active Query) to wake devices
        tokio::spawn(async move {
            let _ = broadcast_query().await;
        });

        // Collect results
        let mut devices: HashMap<String, MdnsInfo> = HashMap::new();
        let timeout_check = tokio::time::sleep(timeout);
        tokio::pin!(timeout_check);

        loop {
            tokio::select! {
                _ = &mut timeout_check => {
                    break;
                }
                Some((ip, target_host, model_hint)) = rx.recv() => {
                    let entry = devices.entry(ip.clone()).or_insert(MdnsInfo { 
                        ip: ip.clone(), 
                        hostname: None, 
                        model: None,
                        device_role: None // could be "printer", "tv"
                    });
                    
                    if let Some(h) = target_host { entry.hostname = Some(h); }
                    if let Some(m) = model_hint { 
                        // Try to clean up model hint
                         entry.model = Some(m); 
                    }
                }
            }
        }
        
        devices
    }
}

async fn listen_mdns(tx: mpsc::Sender<(String, Option<String>, Option<String>)>) -> std::io::Result<()> {
    // Create a socket2 socket for advanced configuration (SO_REUSEADDR) - Vital for mDNS
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(not(windows))]
    socket.set_reuse_port(true)?; 

    let addr = SocketAddr::from(([0, 0, 0, 0], 5353));
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;

    // Join Multicast Group
    let multi_addr = Ipv4Addr::new(224, 0, 0, 251);
    let inter = Ipv4Addr::new(0, 0, 0, 0);
    socket.join_multicast_v4(&multi_addr, &inter)?;

    // Convert to Tokio UdpSocket
    let udp_socket = UdpSocket::from_std(socket.into())?;
    
    let mut buf = [0u8; 4096]; // Increased buffer for full TXT records
    loop {
        if let Ok((len, addr)) = udp_socket.recv_from(&mut buf).await {
            let ip = addr.ip().to_string();
            if ip != "127.0.0.1" {
                // Parse Packet Manually (Basic)
                // We look for PTR records response or TXT records.
                // This is a naive parser looking for keywords in the payload because full DNS parsing is heavy.
                let payload = &buf[..len];
                let payload_str = String::from_utf8_lossy(payload);
                
                let mut host_hint = None;
                let mut model_hint = None;

                // Look for ".local" in the payload which indicates hostname
                if let Some(idx) = payload_str.find(".local") {
                    // Try to extract the word before .local
                    // This is very rough, a real parser would be better but requires `trust-dns` or similar crate dependency change.
                    // For now, let's just send the IP.
                }

                // Apple specific: Look for "model="
                if let Some(idx) = payload_str.find("model=") {
                    let rest = &payload_str[idx+6..];
                    if let Some(end) = rest.find(|c: char| !c.is_alphanumeric() && c != ',') {
                        model_hint = Some(rest[..end].to_string());
                    } else {
                        model_hint = Some(rest.to_string());
                    }
                }
                
                // Device Info TXT
                 if let Some(idx) = payload_str.find("device-info") {
                     // often contains model info
                 }

                let _ = tx.send((ip, host_hint, model_hint)).await;
            }
        }
    }
}

async fn broadcast_query() -> std::io::Result<()> {
    // Use an ephemeral socket for sending
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let target_addr: SocketAddr = "224.0.0.251:5353".parse().unwrap();

    // 1. _services._dns-sd._udp.local
    let query_services = [
        0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
        0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 
        0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64, 
        0x04, 0x5f, 0x75, 0x64, 0x70, 
        0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 
        0x00, 
        0x00, 0x0c, 0x00, 0x01, 
    ];

    // 2. _apple-mobdev2._tcp.local
    let query_apple = [
        0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0e, 0x5f, 0x61, 0x70, 0x70, 0x6c, 0x65, 0x2d, 0x6d, 0x6f, 0x62, 0x64, 0x65, 0x76, 0x32,
        0x04, 0x5f, 0x74, 0x63, 0x70,
        0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
        0x00,
        0x00, 0x0c, 0x00, 0x01,
    ];
    
    // 3. _googlecast._tcp.local
     let query_google = [
        0x00, 0x03, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x0b, 0x5f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x63, 0x61, 0x73, 0x74,
        0x04, 0x5f, 0x74, 0x63, 0x70,
        0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
        0x00,
        0x00, 0x0c, 0x00, 0x01,
    ];


    for _ in 0..3 {
        let _ = socket.send_to(&query_services, target_addr).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = socket.send_to(&query_apple, target_addr).await;
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = socket.send_to(&query_google, target_addr).await;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    
    Ok(())
}
