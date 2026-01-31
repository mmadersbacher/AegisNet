use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::UdpSocket;
use std::collections::HashMap;

pub struct SsdpScanner;

#[derive(Debug, Clone)]
pub struct UpnpDevice {
    pub ip: String,
    pub manufacturer: Option<String>,
    pub model_name: Option<String>,
    pub friendly_name: Option<String>,
    pub server: Option<String>,
}

impl SsdpScanner {
    // Sends M-SEARCH and parses responses
    pub async fn scan(timeout: Duration) -> HashMap<String, UpnpDevice> {
        let mut devices = HashMap::new();
        
        let socket = match UdpSocket::bind("0.0.0.0:0").await {
            Ok(s) => s,
            Err(_) => return devices,
        };
        
        // UPnP M-SEARCH Packet
        let msg = "M-SEARCH * HTTP/1.1\r\n\
                   HOST: 239.255.255.250:1900\r\n\
                   MAN: \"ssdp:discover\"\r\n\
                   MX: 1\r\n\
                   ST: ssdp:all\r\n\r\n";
        
        let target: SocketAddr = "239.255.255.250:1900".parse().unwrap();
        
        // Blast it out a few times
        for _ in 0..3 {
            let _ = socket.send_to(msg.as_bytes(), target).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        
        let mut buf = [0u8; 2048];
        let end_time = tokio::time::Instant::now() + timeout;
        
        while tokio::time::Instant::now() < end_time {
             if let Ok(res) = tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
                 if let Ok((len, addr)) = res {
                     let response = String::from_utf8_lossy(&buf[..len]);
                     let ip = addr.ip().to_string();
                     
                     let mut device = UpnpDevice {
                         ip: ip.clone(),
                         manufacturer: None,
                         model_name: None,
                         friendly_name: None, 
                         server: None,
                     };
                     
                     // Quick Header Parse
                     for line in response.lines() {
                         let lower = line.to_lowercase();
                         if lower.starts_with("server:") {
                             device.server = Some(line[7..].trim().to_string());
                         }
                         if lower.starts_with("usn:") {
                             // Unique Service Name
                         }
                         // LOCATION header points to XML description
                         if lower.starts_with("location:") {
                             let url = line[9..].trim();
                             // Fetch XML details asynchronously if possible (ignoring for now to keep it fast, or maybe minimal fetch?)
                             // Just seeing "Philips Hue" in SERVER header is often enough.
                         }
                     }
                     
                     // Heuristic based on SERVER header
                     if let Some(srv) = &device.server {
                         if srv.contains("Philips Hue") { device.manufacturer = Some("Philips".into()); device.model_name = Some("Hue Bridge".into()); }
                         if srv.contains("Sonos") { device.manufacturer = Some("Sonos".into()); }
                         if srv.contains("Samsung") { device.manufacturer = Some("Samsung".into()); }
                     }

                    devices.insert(ip, device);
                 }
             }
        }
        
        devices
    }
}
