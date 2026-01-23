use reqwest::Client;
use std::time::Duration;
use regex::Regex;

pub struct HttpFingerprint {
    pub server: String,
    pub title: String,
    pub content_type: String,
    pub status: u16,
}

pub async fn analyze(ip: &str, port: u16) -> Option<HttpFingerprint> {
    let scheme = if port == 443 { "https" } else { "http" };
    let url = format!("{}://{}:{}/", scheme, ip, port);
    
    // Ignore cert errors for scanning
    let client = Client::builder()
        .danger_accept_invalid_certs(true)
        .timeout(Duration::from_secs(2))
        .build()
        .ok()?;

    match client.get(&url).send().await {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let headers = resp.headers().clone();
            
            let server = headers.get("server")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("Unknown")
                .to_string();

            let content_type = headers.get("content-type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_string();

            // Try to get title from body if it's text/html
            let mut title = "Unknown".to_string();
            if content_type.contains("html") {
                 if let Ok(text) = resp.text().await {
                     let re = Regex::new(r"(?i)<title>(.*?)</title>").ok()?;
                     if let Some(caps) = re.captures(&text) {
                         if let Some(t) = caps.get(1) {
                             title = t.as_str().trim().to_string();
                         }
                     }
                 }
            }

            Some(HttpFingerprint {
                server,
                title,
                content_type,
                status,
            })
        },
        Err(_) => None,
    }
}
