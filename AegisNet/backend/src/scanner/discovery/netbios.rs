use tokio::net::UdpSocket;
use std::time::Duration;
use tokio::sync::mpsc;
use std::net::SocketAddr;

pub struct NetBiosScanner;

impl NetBiosScanner {
    // Unicast "Node Status" query to every IP in the subnet
    pub async fn scan_subnet(subnet: &str) -> Vec<(String, String)> {
        // Return Vec<(IP, Hostname)>
        let base_ip = subnet.split('/').next().unwrap_or("127.0.0.1");
        let parts: Vec<&str> = base_ip.split('.').collect();
        if parts.len() != 4 { return vec![]; }
        
        let prefix = format!("{}.{}.{}.", parts[0], parts[1], parts[2]);
        let (tx, mut rx) = mpsc::channel(255);

        // Bind a socket for sending/receiving
        // We need to be careful about port binding. NBT uses 137. 
        // Binding to 0 (ephemeral) usually works for sending active probes.
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => std::sync::Arc::new(s),
            Err(_) => return vec![],
        };

        // Header: ID (2), Flags (2), QD (2), AN (2), NS (2), AR (2)
        // Query: Name (34 bytes), Type (2), Class (2)
        // WILDCARD NAME for Node Status: "*" encoded.
        // CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA (32 bytes) + Termuators
        let mut packet = vec![
            0xAB, 0xCD, // ID
            0x00, 0x00, // Flags (Query, etc)
            0x00, 0x01, // QDCOUNT = 1
            0x00, 0x00, // ANCOUNT
            0x00, 0x00, // NSCOUNT
            0x00, 0x00, // ARCOUNT
            
            // NAME "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" (Encoded *)
            0x20, // Length 32
            0x43, 0x4B, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 
            0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 
            0x00, // Terminator
            
            0x00, 0x21, // TYPE = NBSTAT (Node Status)
            0x00, 0x01, // CLASS = IN
        ];

        // Receiver Task
        let socket_recv = socket.clone();
        let tx_res = tx.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            // Listen for 5 seconds max (covering the scan duration)
            let _ = tokio::time::timeout(Duration::from_secs(6), async {
                loop {
                    if let Ok((len, addr)) = socket_recv.recv_from(&mut buf).await {
                        // Parse Hostname from response
                        // Very basic parsing: identifying byte patterns
                        if len > 57 {
                            // Extract Number of Names (Byte 56 approx)
                            // Names start around offset 57.
                            // Each name is 15 bytes + 1 byte type + 2 byte flags.
                            // We just grab the first name as "Hostname"
                            let name_chunk = &buf[57..57+15];
                            let hostname = String::from_utf8_lossy(name_chunk).trim().to_string();
                            let _ = tx_res.send((addr.ip().to_string(), hostname)).await;
                        }
                    }
                }
            }).await;
        });

        // Sender Loop
        for i in 1..255 {
            let target = format!("{}{}:137", prefix, i);
            if let Ok(addr) = target.parse::<SocketAddr>() {
                let socket_send = socket.clone();
                let packet = packet.clone();
                tokio::spawn(async move {
                    let _ = socket_send.send_to(&packet, addr).await;
                });
                // Small delay to prevent flood
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }
        
        drop(tx);
        
        let mut results = Vec::new();
        while let Some(pair) = rx.recv().await {
            results.push(pair);
        }
        results
    }
}
