use crate::scanner::{Host, Service};
use crate::scanner::discovery::{arp, tcp, icmp, passive, netbios, llmnr, udp};
use crate::scanner::fingerprint::{oui, os, http, snmp, smb};
use crate::scanner::vuln::db;

pub struct ScannerCore;

impl ScannerCore {
    pub async fn scan_network(cidr: &str) -> Vec<Host> {
        let mut hosts = Vec::new();
        
        // 1. DISCOVERY PHASE
        // Run ARP and TCP scans in parallel
        // 1. DISCOVERY PHASE
        // Combine Passive Listening, Aggressive ICMP, and TCP Probing
        
        let (passive_ips, icmp_ips, tcp_ips, netbios_res, llmnr_ips, udp_ips) = tokio::join!(
            passive::PassiveSniffer::listen(tokio::time::Duration::from_secs(5)),
            icmp::IcmpScanner::scan_subnet(cidr),
            tcp::TcpDiscovery::scan_subnet(cidr),
            netbios::NetBiosScanner::scan_subnet(cidr),
            llmnr::LlmnrListener::listen(tokio::time::Duration::from_secs(5)),
            udp::UdpScanner::scan_subnet(cidr)
        );

        // Allow some time for ARP table to settle after all that noise
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;

        // Read ARP Table
        let arp_table = arp::ArpScanner::scan().await;

        // Process NetBIOS Names
        let mut netbios_map = std::collections::HashMap::new();
        for (ip, name) in &netbios_res {
            netbios_map.insert(ip.clone(), name.clone());
        }

        // Merge results
        let mut unique_ips = Vec::new();
        let mut seen = std::collections::HashSet::new();
        let mut reliable_hosts = std::collections::HashSet::new(); // IPs confirmed by active/passive means

        // Mark IPs from Passive/ICMP/UDP/NetBIOS/LLMNR as "Reliably Alive"
        for ip in passive_ips.iter().chain(icmp_ips.iter()).chain(udp_ips.iter()).chain(llmnr_ips.iter()).chain(netbios_res.iter().map(|(k,_)| k)) {
            reliable_hosts.insert(ip.clone());
        }

        for ip in passive_ips.into_iter()
            .chain(icmp_ips.into_iter())
            .chain(tcp_ips.into_iter()) 
            .chain(llmnr_ips.into_iter())
            .chain(udp_ips.into_iter())
            .chain(netbios_map.keys().cloned())
            .chain(arp_table.keys().cloned()) {
            
            if seen.insert(ip.clone()) {
                unique_ips.push(ip);
            }
        }

        // 2. ENRICHMENT PHASE
        for ip in unique_ips {
            if let Some(host) = Self::enrich_host(ip, &arp_table, &netbios_map, &reliable_hosts).await {
                hosts.push(host);
            }
        }
        
        // Deduplicate hosts by IP just in case
        hosts.dedup_by(|a, b| a.ip == b.ip);
        
        // Sort
        hosts.sort_by(|a, b| {
             let a_last = a.ip.split('.').last().unwrap_or("0").parse::<u8>().unwrap_or(0);
             let b_last = b.ip.split('.').last().unwrap_or("0").parse::<u8>().unwrap_or(0);
             a_last.cmp(&b_last)
        });

        hosts
    }

    async fn enrich_host(ip: String, arp_table: &std::collections::HashMap<String, String>, netbios_map: &std::collections::HashMap<String, String>, reliable_hosts: &std::collections::HashSet<String>) -> Option<Host> {
        // Filter Broadcast / Multicast
        if ip.ends_with(".255") || ip.ends_with(".0") || ip.starts_with("224.") || ip.starts_with("239.") { 
            return None; 
        }

        // Get MAC
        let mac = arp_table.get(&ip).cloned().unwrap_or_else(|| "00:00:00:00:00:00".to_string());
        if mac == "FF:FF:FF:FF:FF:FF" { return None; } // Exclude Broadcast MAC
        
        // FINGERPRINT: Vendor
        let vendor = oui::OuiDb::lookup(&mac);
        
        // NetBIOS Name Preference
        let hostname = if let Some(nb_name) = netbios_map.get(&ip) {
            nb_name.clone()
        } else {
            vendor.clone() // Fallback
        };
        
        // SCAN: Ports (Re-Verify)
        let open_ports = quick_port_scan(&ip).await;
        // Optimization: If we found it via active means (NetBIOS/AR/Passive/UDP), we keep it even if ports closed.
        // We only drop if it's NOT reliable AND has no ports (ghosts from stale ARP)
        if open_ports.is_empty() && !netbios_map.contains_key(&ip) && !reliable_hosts.contains(&ip) { return None; }

        // FINGERPRINT: OS
        let os_family = os::OsFingerprint::infer(64, &open_ports);
        
        // CLASSIFY: Device Type
        let device_type = if vendor.contains("Apple") || vendor.contains("Samsung") { "Mobile/Tablet".to_string() }
                          else if open_ports.contains(&80) || open_ports.contains(&443) { "Server/Web".to_string() }
                          else if open_ports.contains(&3389) || netbios_map.contains_key(&ip) { "Workstation (Windows)".to_string() }
                          else { "Network Device".to_string() };

        // VULN: CVEs
        let mut services = Vec::new();
        let mut host_risk = 0;
        
        for port in &open_ports {
            let mut banner = String::from("Unknown");
            let mut service_name = "tcp".to_string();

            // SMB Fingerprinting
            if *port == 445 {
                 if let Some(info) = smb::probe(&ip).await {
                     banner = format!("SMB: {}", info.native_os);
                     service_name = "smb".into();
                 } else {
                     banner = crate::scanner::fingerprint::banner::ServiceBanner::grab(&ip, *port).await;
                 }
            } else if [80, 443, 8080, 8081, 3000, 5000, 8000].contains(port) {
                if let Some(info) = http::analyze(&ip, *port).await {
                    banner = format!("HTTP {} | Server: {} | Title: {}", info.status, info.server, info.title);
                    service_name = if *port == 443 { "https".into() } else { "http".into() };
                } else {
                     // Fallback to basic grab if HTTP fails
                     banner = crate::scanner::fingerprint::banner::ServiceBanner::grab(&ip, *port).await;
                }
            } else {
                 // Standard Banner Grab
                 banner = crate::scanner::fingerprint::banner::ServiceBanner::grab(&ip, *port).await;
            }

            let vulns = db::CveDb::check(*port, &banner);
            if !vulns.is_empty() { host_risk += 10; }
            
            services.push(Service {
                port: *port,
                protocol: "TCP".into(),
                name: service_name, 
                banner,
                version: "".into(),
                cves: vulns.iter().map(|v| format!("{}|{}", v.id, v.url)).collect(), 
            });
        }

        // UDP Service: SNMP (Active Probe)
        if let Some(snmp_info) = snmp::fingerprint(&ip).await {
             host_risk += 5; // SNMP visible is info leak
             services.push(Service {
                port: 161,
                protocol: "UDP".into(),
                name: "snmp".into(),
                banner: snmp_info.sys_descr.clone(),
                version: "v1/v2c".into(),
                cves: vec![],
             });
             
             // Auto-Check if device_type matches
             if snmp_info.sys_descr.to_lowercase().contains("printer") {
                 // We can't mutate valid device_type easily here without mutable access, 
                 // but we can use this info.
                 // For now, the banner is enough.
             }
        }

        Some(Host {
            ip,
            mac,
            hostname,
            vendor,
            os_family,
            device_type,
            open_ports,
            services,
            risk_score: host_risk,
        })
    }
}

async fn quick_port_scan(ip: &str) -> Vec<u16> {
    use tokio::net::TcpStream;
    use std::time::Duration;
    let ports = [21, 22, 23, 80, 443, 445, 3389, 8080];
    let mut open = Vec::new();
    for port in ports {
        let addr = format!("{}:{}", ip, port);
        if tokio::time::timeout(Duration::from_millis(40), TcpStream::connect(addr)).await.is_ok() {
            open.push(port);
        }
    }
    open
}
