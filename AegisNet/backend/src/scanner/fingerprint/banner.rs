use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use std::time::Duration;

pub struct ServiceBanner;

impl ServiceBanner {
    pub async fn grab(ip: &str, port: u16) -> String {
        let addr = format!("{}:{}", ip, port);
        // Short timeout for banner grab
        let timeout = Duration::from_millis(500);

        let connect_result = tokio::time::timeout(timeout, TcpStream::connect(&addr)).await;
        
        if let Ok(Ok(mut stream)) = connect_result {
             // Send a probe depending on port
             let probe: &[u8] = match port {
                 80 | 8080 => b"HEAD / HTTP/1.0\r\n\r\n",
                 _ => b"\r\n", 
             };
             
             let _ = stream.write_all(probe).await;
             
             let mut buffer = [0; 512];
             let read_result = tokio::time::timeout(timeout, stream.read(&mut buffer)).await;
             
             if let Ok(Ok(n)) = read_result {
                 if n > 0 {
                     return String::from_utf8_lossy(&buffer[..n]).trim().to_string();
                 }
             }
        }
        
        return "Unknown".to_string();
    }
}
