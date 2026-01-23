use serde::Serialize;

#[derive(Serialize, Clone)]
pub struct Vulnerability {
    pub cve_id: String,
    pub severity: String,
    pub description: String,
    pub affected_port: u16,
}

pub struct VulnerabilityScanner;

impl VulnerabilityScanner {
    // Mock CVE checking based on open ports
    pub fn scan(open_ports: &[u16]) -> Vec<Vulnerability> {
        let mut vulns = Vec::new();

        for port in open_ports {
            match port {
                21 => vulns.push(Vulnerability {
                    cve_id: "CVE-2011-2523".to_string(),
                    severity: "CRITICAL".to_string(),
                    description: "vsftpd 2.3.4 Backdoor Command Execution".to_string(),
                    affected_port: 21
                }),
                22 => vulns.push(Vulnerability {
                    cve_id: "CVE-2016-0777".to_string(),
                    severity: "HIGH".to_string(),
                    description: "OpenSSH Roaming Information Disclosure".to_string(),
                    affected_port: 22
                }),
                23 => vulns.push(Vulnerability {
                    cve_id: "CVE-2020-10188".to_string(),
                    severity: "HIGH".to_string(),
                    description: "Telnet Buffer Overflow".to_string(),
                    affected_port: 23
                }),
                445 => vulns.push(Vulnerability {
                    cve_id: "CVE-2017-0144".to_string(),
                    severity: "CRITICAL".to_string(),
                    description: "EternalBlue SMB Remote Code Execution".to_string(),
                    affected_port: 445
                }),
                3389 => vulns.push(Vulnerability {
                    cve_id: "CVE-2019-0708".to_string(),
                    severity: "CRITICAL".to_string(),
                    description: "BlueKeep RDP Remote Code Execution".to_string(),
                    affected_port: 3389
                }),
                 _ => {}
            }
        }
        vulns
    }
}
