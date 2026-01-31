use std::collections::HashMap;
use tokio::process::Command;

pub struct ArpScanner;

impl ArpScanner {
    pub async fn scan() -> HashMap<String, String> {
        let mut map = HashMap::new();
        // Windows 'arp -a'
        let output = match Command::new("arp").arg("-a").output().await {
            Ok(o) => o,
            Err(_) => return map,
        };
        
        let stdout = String::from_utf8_lossy(&output.stdout);
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
                 if !ip.is_empty() && !mac.is_empty() {
                     // Filter multicast/broadcast
                     if !ip.starts_with("224.") && !ip.starts_with("239.") && !ip.starts_with("255.") && !ip.ends_with(".255") {
                        map.insert(ip, mac);
                     }
                 }
            }
        }
        map
    }
}
