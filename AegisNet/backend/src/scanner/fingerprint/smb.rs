use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use std::time::Duration;

pub struct SmbInfo {
    pub native_os: String,
    pub native_lan_man: String,
}

pub async fn probe(ip: &str) -> Option<SmbInfo> {
    let addr = format!("{}:445", ip);
    let mut stream = tokio::time::timeout(Duration::from_secs(1), TcpStream::connect(addr)).await.ok()?.ok()?;

    // SMB1 Negotiate Protocol Request (NT LM 0.12)
    // Needs NetBIOS Session Service Header (4 bytes) + SMB Header (32 bytes) + WordCount (1) + ByteCount (2) + Body
    let packet: [u8; 51] = [
        0x00, 0x00, 0x00, 0x2F, // NetBIOS Length (47)
        0xFF, 0x53, 0x4D, 0x42, // Protocol: 0xFF SMB
        0x72, // Command: Negotiate Protocol
        0x00, 0x00, 0x00, 0x00, // Status
        0x18, // Flags (Canocicalized Pathnames, Case Insensitive)
        0x01, 0x20, // Flags2 (Unicode, Error Code)
        0x00, 0x00, // PID High
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Security signature / Reserved
        0x00, 0x00, // Reserved
        0x00, 0x00, // TID
        0x00, 0x00, // PID Low
        0x00, 0x00, // UID
        0x00, 0x00, // MID
        0x00, // Word Count 0
        0x0C, 0x00, // Byte Count 12
        // Dialects
        0x02, 0x4E, 0x54, 0x20, 0x4C, 0x4D, 0x20, 0x30, 0x2E, 0x31, 0x32, 0x00, // "NT LM 0.12"
    ];

    stream.write_all(&packet).await.ok()?;

    let mut buf = [0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(1), stream.read(&mut buf)).await.ok()?.ok()?;
    
    if n > 40 {
        // Very basic extraction of strings from the end of the packet
        // SMB1 response puts Native OS and Native Lan Man at the end as ASCII/Unicode strings.
        // We can just scan for printable strings > 4 chars
        let content = &buf[..n];
        let s = String::from_utf8_lossy(content);
        
        // Split by null bytes or common patterns?
        // Heuristic: Find "Windows"
        let mut native_os = "Unknown".to_string();
        if let Some(idx) = s.find("Windows") {
             // Take until next weird char
             let end = s[idx..].find(|c: char| !c.is_ascii_graphic() && c != ' ').unwrap_or(s.len() - idx);
             native_os = s[idx..idx+end].to_string();
        }

        return Some(SmbInfo {
            native_os,
            native_lan_man: "Unknown".to_string(), // Keep simple
        });
    }

    None
}
