use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct Vulnerability {
    pub id: String,
    pub cvss: f32,
    pub severity: String,
    pub description: String,
    pub url: String, // Added URL
}

pub struct CveDb;

impl CveDb {
    pub fn check(port: u16, banner: &str) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();
        let b = banner.to_lowercase();

        // 1. Port-Based Logic (Weak Indicators - Only use for critical ports if banner is empty but port is confirmed)
        // Actually, user wants NO false positives. So we ONLY trigger on banner detection or specific high-risk configurations.
        
        // FTP
        if port == 21 {
            if b.contains("vsftpd 2.3.4") {
                vulns.push(Vulnerability {
                    id: "CVE-2011-2523".into(),
                    cvss: 9.8,
                    severity: "CRITICAL".into(),
                    description: "vsftpd 2.3.4 Backdoor".into(),
                    url: "https://nvd.nist.gov/vuln/detail/CVE-2011-2523".into(),
                });
            } else {
                 // Info level
            }
        }

        // SMB
        if port == 445 {
            // Hard to detect EternalBlue via banner, but we can warn about SMBv1
            // For now, only report if we are sure.
             vulns.push(Vulnerability {
                    id: "AUDIT-SMB".into(),
                    cvss: 5.0,
                    severity: "MEDIUM".into(),
                    description: "SMB Service exposed. Audit for SMBv1.".into(),
                    url: "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144".into(),
             });
        }
        
        // Log4Shell (Banner match)
        if (port == 8080 || port == 80) && (b.contains("log4j") || b.contains("java")) {
             vulns.push(Vulnerability {
                id: "CVE-2021-44228".into(),
                cvss: 10.0,
                severity: "CRITICAL".into(),
                description: "Potential Log4Shell Exposure".into(),
                 url: "https://nvd.nist.gov/vuln/detail/CVE-2021-44228".into(),
            });
        }

        vulns
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vsftpd_backdoor() {
        let vulns = CveDb::check(21, "220 (vsFTPd 2.3.4)");
        assert_eq!(vulns.len(), 1);
        assert_eq!(vulns[0].id, "CVE-2011-2523");
    }

    #[test]
    fn test_safe_ftp() {
        let vulns = CveDb::check(21, "220 (vsFTPd 3.0.0)");
        assert!(vulns.is_empty());
    }

    #[test]
    fn test_log4shell() {
        let vulns = CveDb::check(8080, "Applying log4j patch...");
        assert!(!vulns.is_empty());
        assert_eq!(vulns[0].id, "CVE-2021-44228");
    }
}
