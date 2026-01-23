use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use socket2::{Socket, Domain, Type, Protocol};
use std::time::Duration;
use std::collections::HashSet;
use tokio::sync::mpsc;

pub struct PassiveSniffer;

impl PassiveSniffer {
    pub async fn listen(timeout: Duration) -> Vec<String> {
        let (tx, mut rx) = mpsc::channel(100);
        
        // Spawn listeners for mDNS and SSDP
        let tx_mdns = tx.clone();
        tokio::spawn(async move {
            let _ = listen_multicast(5353, "224.0.0.251", tx_mdns, true).await;
        });

        let tx_ssdp = tx.clone();
        tokio::spawn(async move {
            let _ = listen_multicast(1900, "239.255.255.250", tx_ssdp, false).await;
        });

        // Collect results for the duration
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

async fn listen_multicast(port: u16, bind_addr: &str, tx: mpsc::Sender<String>, active_mdns: bool) -> std::io::Result<()> {
    // Standard UDP socket bind
    let socket = UdpSocket::bind(format!("0.0.0.0:{}", port)).await?;
    
    // Join multicast group
    if let Ok(addr) = bind_addr.parse::<Ipv4Addr>() {
        let _ = socket.join_multicast_v4(addr, Ipv4Addr::UNSPECIFIED);
    }
    
    // Set multicast loopback so we don't hear ourselves (optional but good)
    let _ = socket.set_multicast_loop_v4(false);

    // If this is mDNS, send an ACTIVE QUERY to Force responses
    if active_mdns {
        let target_addr: SocketAddr = format!("{}:{}", bind_addr, port).parse().unwrap();
        // RAW mDNS Query for "_services._dns-sd._udp.local" (PTR)
        let query = [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Header
            0x09, 0x5f, 0x73, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x73, // _services
            0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d, 0x73, 0x64, // _dns-sd
            0x04, 0x5f, 0x75, 0x64, 0x70, // _udp
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, // local
            0x00, // End of name
            0x00, 0x0c, // Type PTR
            0x00, 0x01, // Class IN
        ];
        
        // Blast it out a few times
        tokio::spawn(async move {
            // Use a separate ephemeral socket for sending queries to avoid cloning issues
            if let Ok(sender) = UdpSocket::bind("0.0.0.0:0").await {
                for _ in 0..3 {
                     let _ = sender.send_to(&query, target_addr).await;
                     tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        });
    }

    let mut buf = [0u8; 1024];
    loop {
        if let Ok((_len, addr)) = socket.recv_from(&mut buf).await {
            let ip = addr.ip().to_string();
            // Filter local IPs/Loopback if needed, but for now just send it
            if ip != "127.0.0.1" {
                let _ = tx.send(ip).await;
            }
        }
    }
}
