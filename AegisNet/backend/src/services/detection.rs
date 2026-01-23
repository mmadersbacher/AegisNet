use regex::Regex;
use crate::services::normalization::NormalizedLog;

pub struct DetectionEngine {
    rules: Vec<Rule>,
}

struct Rule {
    name: String,
    pattern: Regex,
    severity: String,
}

impl DetectionEngine {
    pub fn new() -> Self {
        // Hardcoded rules for MVP. In real app, load from DB/YAML.
        let rules = vec![
            Rule {
                name: "SSH Failed Login".to_string(),
                pattern: Regex::new(r"(?i)failed password for").unwrap(),
                severity: "HIGH".to_string(),
            },
             Rule {
                name: "Sudo Abuse".to_string(),
                pattern: Regex::new(r"(?i)sudo:.*COMMAND").unwrap(),
                severity: "MEDIUM".to_string(),
            },
        ];
        
        Self { rules }
    }

    pub fn analyze(&self, log: &NormalizedLog) -> Option<String> {
        for rule in &self.rules {
            if rule.pattern.is_match(&log.message) {
                return Some(format!("ALERT: [{}] detected in log from {}", rule.name, log.source));
            }
        }
        None
    }
}
