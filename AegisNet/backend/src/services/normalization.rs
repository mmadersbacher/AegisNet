use serde_json::Value;
use chrono::{DateTime, Utc};
use regex::Regex;

pub struct NormalizedLog {
    pub source: String,
    pub level: String,
    pub message: String,
    pub event_time: DateTime<Utc>,
    pub metadata: Option<Value>,
}

pub fn normalize_log(raw_content: &str, source: &str) -> NormalizedLog {
    // Simple heuristic: Try to parse as JSON first, otherwise treat as Syslog/Plaintext
    if let Ok(json_val) = serde_json::from_str::<Value>(raw_content) {
        return normalize_json(json_val, source, raw_content);
    }

    normalize_plaintext(raw_content, source)
}

fn normalize_json(json: Value, source: &str, _raw: &str) -> NormalizedLog {
    let level = json["level"].as_str().unwrap_or("INFO").to_uppercase();
    let message = json["message"].as_str()
        .or_else(|| json["msg"].as_str())
        .unwrap_or("No message provided")
        .to_string();
    
    // Attempt timestamp parsing or default to now
    let event_time = Utc::now(); 

    NormalizedLog {
        source: source.to_string(),
        level,
        message,
        event_time,
        metadata: Some(json),
    }
}

fn normalize_plaintext(raw: &str, source: &str) -> NormalizedLog {
    // Basic Syslog Regex (very simplified)
    // Example: "Jan 23 10:00:00 myhost sshd[123]: Failed password..."
    // For now, just wrap it.
    
    let level = if raw.to_lowercase().contains("error") || raw.to_lowercase().contains("fail") {
        "ERROR"
    } else if raw.to_lowercase().contains("warn") {
        "WARN"
    } else {
        "INFO"
    };

    NormalizedLog {
        source: source.to_string(),
        level: level.to_string(),
        message: raw.to_string(),
        event_time: Utc::now(),
        metadata: None,
    }
}
