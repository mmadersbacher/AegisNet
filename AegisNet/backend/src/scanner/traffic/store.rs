use std::collections::HashMap;
use std::sync::Arc;
use dashmap::DashMap;
use serde::Serialize;
use std::time::SystemTime;

#[derive(Debug, Clone, Serialize)]
pub struct TrafficFlow {
    pub src_ip: String,
    pub dst_ip: String,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: String,
    pub service: String,
    pub application: Option<String>,
    pub sni: Option<String>,
    pub dns_query: Option<String>,
    pub http_host: Option<String>,         // NEW: HTTP Host header
    pub resolved_domain: Option<String>,   // NEW: Multiple sources combined
    pub bytes: u64,
    pub packet_count: u64,
    pub last_seen: u64,
    pub category: String,
    pub insight: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct DeviceTraffic {
    pub ip: String,
    pub total_bytes: u64,
    pub total_packets: u64,
    pub protocols: HashMap<String, u64>,
    pub top_services: HashMap<String, u64>,
    pub top_destinations: HashMap<String, u64>,
}

#[derive(Clone)]
pub struct TrafficStore {
    pub flows: Arc<DashMap<String, TrafficFlow>>,
    pub device_stats: Arc<DashMap<String, DeviceTraffic>>,
    // DNS Cache: Maps IP -> Domain from DNS responses we've seen
    dns_cache: Arc<DashMap<String, String>>,
    // Reverse DNS Cache: Populated via background lookups
    rdns_cache: Arc<DashMap<String, String>>,
}

impl TrafficStore {
    pub fn new() -> Self {
        Self {
            flows: Arc::new(DashMap::new()),
            device_stats: Arc::new(DashMap::new()),
            dns_cache: Arc::new(DashMap::new()),
            rdns_cache: Arc::new(DashMap::new()),
        }
    }

    pub fn process_packet(&self, src_ip: String, dst_ip: String, len: u64, proto: u8, payload: &[u8]) {
        let (protocol_str, src_port, dst_port, service, mut sni, dns_query, http_host, tcp_payload) = 
            self.parse_transport_layer(proto, payload);

        // === MULTI-LAYER DOMAIN RESOLUTION ===
        
        // 1. Cache DNS A-record responses (query -> IP mapping)
        if let Some(ref domain) = dns_query {
            // The dst_ip in a DNS query response often contains resolved IPs in DNS answers
            // But here we're capturing the query domain and associating with src (the resolver target)
            self.dns_cache.insert(dst_ip.clone(), domain.clone());
        }
        
        // 2. Try to extract domain via multiple methods
        let mut resolved_domain: Option<String> = None;
        
        // Priority 1: TLS SNI (most reliable when available)
        if sni.is_some() {
            resolved_domain = sni.clone();
        }
        // Priority 2: HTTP Host header (plaintext HTTP)
        else if http_host.is_some() {
            resolved_domain = http_host.clone();
        }
        // Priority 3: DNS Cache (we saw a DNS query to this IP earlier)
        else if let Some(cached) = self.dns_cache.get(&dst_ip) {
            resolved_domain = Some(cached.value().clone());
            // Also populate SNI field for display purposes
            sni = Some(cached.value().clone());
        }
        // Priority 4: Known IP range database
        else if let Some(provider) = self.identify_by_ip_range(&dst_ip) {
            resolved_domain = Some(provider.clone());
        }
        // Priority 5: Reverse DNS cache
        else if let Some(rdns) = self.rdns_cache.get(&dst_ip) {
            resolved_domain = Some(rdns.value().clone());
        }
        // Priority 6: Trigger async reverse DNS lookup (won't block)
        else {
            self.trigger_rdns_lookup(&dst_ip);
        }

        let application = self.identify_application(&dst_ip, dst_port, resolved_domain.as_deref());
        let category = self.categorize_traffic(&service, dst_port, application.as_deref());
        let insight = self.generate_insight(&dst_ip, &service, &category, application.as_deref(), resolved_domain.as_deref());

        // Update Flow
        let key = format!("{}:{}|{}:{}|{}", src_ip, src_port, dst_ip, dst_port, protocol_str);
        
        self.flows.entry(key).and_modify(|f| {
            f.bytes += len;
            f.packet_count += 1;
            f.last_seen = now_unix();
            if f.sni.is_none() && sni.is_some() { f.sni = sni.clone(); }
            if f.dns_query.is_none() && dns_query.is_some() { f.dns_query = dns_query.clone(); }
            if f.http_host.is_none() && http_host.is_some() { f.http_host = http_host.clone(); }
            if f.resolved_domain.is_none() && resolved_domain.is_some() { f.resolved_domain = resolved_domain.clone(); }
            if f.application.is_none() && application.is_some() { f.application = application.clone(); }
        }).or_insert(TrafficFlow {
            src_ip: src_ip.clone(),
            dst_ip: dst_ip.clone(),
            src_port,
            dst_port,
            protocol: protocol_str.to_string(),
            service: service.clone(),
            application,
            sni,
            dns_query,
            http_host,
            resolved_domain,
            bytes: len,
            packet_count: 1,
            last_seen: now_unix(),
            category,
            insight,
        });

        // Update Device Stats
        self.device_stats.entry(src_ip.clone()).and_modify(|s| {
            s.total_bytes += len;
            s.total_packets += 1;
            *s.protocols.entry(protocol_str.to_string()).or_insert(0) += len;
            *s.top_services.entry(service.clone()).or_insert(0) += len;
            *s.top_destinations.entry(dst_ip.clone()).or_insert(0) += len;
        }).or_insert_with(|| {
            let mut dev = DeviceTraffic {
                ip: src_ip,
                total_bytes: len,
                total_packets: 1,
                protocols: HashMap::new(),
                top_services: HashMap::new(),
                top_destinations: HashMap::new(),
            };
            dev.protocols.insert(protocol_str.to_string(), len);
            dev.top_services.insert(service, len);
            dev.top_destinations.insert(dst_ip, len);
            dev
        });
    }

    // === KNOWN IP RANGES DATABASE ===
    fn identify_by_ip_range(&self, ip: &str) -> Option<String> {
        let parts: Vec<u8> = ip.split('.').filter_map(|s| s.parse().ok()).collect();
        if parts.len() != 4 { return None; }
        
        let (a, b, c, _d) = (parts[0], parts[1], parts[2], parts[3]);
        
        // Google (8.8.x.x, 8.34-35.x.x, 34.x.x.x, 35.x.x.x, 64.233.x.x, 66.102.x.x, 66.249.x.x, 72.14.x.x, 74.125.x.x, 108.177.x.x, 142.250-251.x.x, 172.217.x.x, 173.194.x.x, 209.85.x.x, 216.58.x.x, 216.239.x.x)
        if a == 8 && (b == 8 || b == 34 || b == 35) { return Some("google.com".into()); }
        if a == 34 || a == 35 { return Some("google.com".into()); }
        if a == 64 && b == 233 { return Some("google.com".into()); }
        if a == 66 && (b == 102 || b == 249) { return Some("google.com".into()); }
        if a == 72 && b == 14 { return Some("google.com".into()); }
        if a == 74 && b == 125 { return Some("google.com".into()); }
        if a == 108 && b == 177 { return Some("google.com".into()); }
        if a == 142 && (b >= 250 && b <= 251) { return Some("google.com".into()); }
        if a == 172 && b == 217 { return Some("google.com".into()); }
        if a == 173 && b == 194 { return Some("google.com".into()); }
        if a == 209 && b == 85 { return Some("google.com".into()); }
        if a == 216 && (b == 58 || b == 239) { return Some("google.com".into()); }
        
        // YouTube (same as Google but we can detect via port patterns)
        // Netflix (23.246.x.x, 37.77.x.x, 45.57.x.x, 64.120.x.x, 66.197.x.x, 108.175.x.x, 185.2.220.x, 185.9.188.x, 192.173.x.x, 198.38.x.x, 198.45.x.x, 207.45.x.x, 208.75.x.x)
        if a == 23 && b == 246 { return Some("netflix.com".into()); }
        if a == 37 && b == 77 { return Some("netflix.com".into()); }
        if a == 45 && b == 57 { return Some("netflix.com".into()); }
        if a == 64 && b == 120 { return Some("netflix.com".into()); }
        if a == 66 && b == 197 { return Some("netflix.com".into()); }
        if a == 108 && b == 175 { return Some("netflix.com".into()); }
        if a == 185 && (b == 2 || b == 9) { return Some("netflix.com".into()); }
        if a == 192 && b == 173 { return Some("netflix.com".into()); }
        if a == 198 && (b == 38 || b == 45) { return Some("netflix.com".into()); }
        if a == 207 && b == 45 { return Some("netflix.com".into()); }
        if a == 208 && b == 75 { return Some("netflix.com".into()); }
        
        // Facebook/Meta (31.13.x.x, 66.220.x.x, 69.63.x.x, 69.171.x.x, 74.119.x.x, 102.132.x.x, 129.134.x.x, 157.240.x.x, 173.252.x.x, 179.60.x.x, 185.60.x.x, 204.15.x.x)
        if a == 31 && b == 13 { return Some("facebook.com".into()); }
        if a == 66 && b == 220 { return Some("facebook.com".into()); }
        if a == 69 && (b == 63 || b == 171) { return Some("facebook.com".into()); }
        if a == 74 && b == 119 { return Some("facebook.com".into()); }
        if a == 102 && b == 132 { return Some("facebook.com".into()); }
        if a == 129 && b == 134 { return Some("facebook.com".into()); }
        if a == 157 && b == 240 { return Some("facebook.com".into()); }
        if a == 173 && b == 252 { return Some("facebook.com".into()); }
        if a == 179 && b == 60 { return Some("facebook.com".into()); }
        if a == 185 && b == 60 { return Some("facebook.com".into()); }
        if a == 204 && b == 15 { return Some("facebook.com".into()); }
        
        // Microsoft/Azure (13.x.x.x, 20.x.x.x, 40.x.x.x, 51.x.x.x, 52.x.x.x, 65.52-55.x.x, 104.40-47.x.x, 131.253.x.x, 134.170.x.x, 137.116-117.x.x, 157.55-56.x.x, 168.61-63.x.x, 191.232-239.x.x, 204.79.x.x)
        if a == 13 || a == 20 || a == 40 || a == 51 || a == 52 { return Some("microsoft.com".into()); }
        if a == 65 && (b >= 52 && b <= 55) { return Some("microsoft.com".into()); }
        if a == 104 && (b >= 40 && b <= 47) { return Some("microsoft.com".into()); }
        if a == 131 && b == 253 { return Some("microsoft.com".into()); }
        if a == 134 && b == 170 { return Some("microsoft.com".into()); }
        if a == 137 && (b == 116 || b == 117) { return Some("microsoft.com".into()); }
        if a == 157 && (b == 55 || b == 56) { return Some("microsoft.com".into()); }
        if a == 168 && (b >= 61 && b <= 63) { return Some("microsoft.com".into()); }
        if a == 191 && (b >= 232 && b <= 239) { return Some("microsoft.com".into()); }
        if a == 204 && b == 79 { return Some("microsoft.com".into()); }
        
        // Amazon/AWS (3.x.x.x, 18.x.x.x, 34.x.x.x, 35.x.x.x, 44.x.x.x, 50.x.x.x, 52.x.x.x, 54.x.x.x, 63.x.x.x, 72.x.x.x, 75.x.x.x, 99.x.x.x, 107.x.x.x, 174.x.x.x, 176.x.x.x, 184.x.x.x, 204.x.x.x, 205.x.x.x)
        if a == 3 || a == 18 || a == 44 || a == 50 || a == 54 { return Some("amazon.com".into()); }
        if a == 99 || a == 107 || a == 174 || a == 176 { return Some("amazon.com".into()); }
        
        // Apple (17.x.x.x)
        if a == 17 { return Some("apple.com".into()); }
        
        // Cloudflare (104.16-31.x.x, 172.64-71.x.x, 173.245.x.x, 188.114.x.x, 190.93.x.x, 197.234.x.x, 198.41.x.x)
        if a == 104 && (b >= 16 && b <= 31) { return Some("cloudflare.com".into()); }
        if a == 172 && (b >= 64 && b <= 71) { return Some("cloudflare.com".into()); }
        if a == 173 && b == 245 { return Some("cloudflare.com".into()); }
        if a == 188 && b == 114 { return Some("cloudflare.com".into()); }
        if a == 190 && b == 93 { return Some("cloudflare.com".into()); }
        if a == 197 && b == 234 { return Some("cloudflare.com".into()); }
        if a == 198 && b == 41 { return Some("cloudflare.com".into()); }
        if a == 1 && b == 1 { return Some("cloudflare-dns.com".into()); } // 1.1.1.1
        
        // Discord (162.159.x.x - often behind Cloudflare)
        if a == 162 && b == 159 { return Some("discord.com".into()); }
        
        // Twitch (23.160.x.x, 52.223.x.x, 99.181.x.x, 185.42.x.x, 192.16.x.x)
        if a == 23 && b == 160 { return Some("twitch.tv".into()); }
        if a == 185 && b == 42 { return Some("twitch.tv".into()); }
        if a == 99 && b == 181 { return Some("twitch.tv".into()); }
        
        // Steam/Valve (103.10.x.x, 146.66.x.x, 155.133.x.x, 162.254.x.x, 185.25.x.x, 192.69.x.x, 205.196.x.x, 208.64.x.x)
        if a == 103 && b == 10 { return Some("steampowered.com".into()); }
        if a == 146 && b == 66 { return Some("steampowered.com".into()); }
        if a == 155 && b == 133 { return Some("steampowered.com".into()); }
        if a == 162 && b == 254 { return Some("steampowered.com".into()); }
        if a == 185 && b == 25 { return Some("steampowered.com".into()); }
        if a == 192 && b == 69 { return Some("steampowered.com".into()); }
        if a == 205 && b == 196 { return Some("steampowered.com".into()); }
        if a == 208 && b == 64 { return Some("steampowered.com".into()); }
        
        // Spotify (35.186.x.x, 78.31.x.x, 193.182.x.x, 194.132.x.x)
        if a == 35 && b == 186 { return Some("spotify.com".into()); }
        if a == 78 && b == 31 { return Some("spotify.com".into()); }
        if a == 193 && b == 182 { return Some("spotify.com".into()); }
        if a == 194 && b == 132 { return Some("spotify.com".into()); }
        
        // TikTok/ByteDance (161.117.x.x, 152.199.x.x)
        if a == 161 && b == 117 { return Some("tiktok.com".into()); }
        if a == 152 && b == 199 { return Some("tiktok.com".into()); }
        
        // Twitter/X (104.244.x.x, 192.133.x.x)
        if a == 104 && b == 244 { return Some("twitter.com".into()); }
        if a == 192 && b == 133 { return Some("twitter.com".into()); }
        
        // Pornhub/MindGeek (66.254.x.x, 185.88.x.x, 216.18.x.x)
        if a == 66 && b == 254 { return Some("pornhub.com".into()); }
        if a == 185 && b == 88 { return Some("pornhub.com".into()); }
        if a == 216 && b == 18 { return Some("pornhub.com".into()); }
        
        // Akamai CDN (23.x.x.x partial, 92.122-123.x.x, 95.100-101.x.x, 184.24-31.x.x)
        if a == 92 && (b == 122 || b == 123) { return Some("akamai.net".into()); }
        if a == 95 && (b >= 100 && b <= 101) { return Some("akamai.net".into()); }
        if a == 184 && (b >= 24 && b <= 31) { return Some("akamai.net".into()); }
        
        // Fastly CDN (151.101.x.x, 199.232.x.x)
        if a == 151 && b == 101 { return Some("fastly.net".into()); }
        if a == 199 && b == 232 { return Some("fastly.net".into()); }
        
        None
    }

    fn trigger_rdns_lookup(&self, ip: &str) {
        // Only attempt if not already cached
        if self.rdns_cache.contains_key(ip) { return; }
        
        let ip_clone = ip.to_string();
        let cache = self.rdns_cache.clone();
        
        // Fire-and-forget async lookup
        std::thread::spawn(move || {
            if let Ok(names) = dns_lookup::lookup_addr(&ip_clone.parse().unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(0,0,0,0)))) {
                cache.insert(ip_clone, names);
            }
        });
    }

    fn parse_transport_layer<'a>(&self, proto: u8, payload: &'a [u8]) -> (&'static str, u16, u16, String, Option<String>, Option<String>, Option<String>, &'a [u8]) {
        match proto {
            6 => self.parse_tcp(payload),
            17 => self.parse_udp(payload),
            1 => ("ICMP", 0, 0, "ICMP".to_string(), None, None, None, &payload[0..0]),
            2 => ("IGMP", 0, 0, "IGMP".to_string(), None, None, None, &payload[0..0]),
            _ => ("OTHER", 0, 0, format!("Proto-{}", proto), None, None, None, &payload[0..0]),
        }
    }

    fn parse_tcp<'a>(&self, payload: &'a [u8]) -> (&'static str, u16, u16, String, Option<String>, Option<String>, Option<String>, &'a [u8]) {
        if payload.len() < 20 {
            return ("TCP", 0, 0, "TCP".to_string(), None, None, None, &[]);
        }
        
        let src_port = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
        let data_offset = ((payload[12] >> 4) * 4) as usize;
        
        let tcp_payload = if payload.len() > data_offset { &payload[data_offset..] } else { &[] };
        
        let service = self.port_to_service(dst_port, src_port);
        let sni = self.extract_tls_sni(tcp_payload);
        let http_host = self.extract_http_host(tcp_payload);
        
        ("TCP", src_port, dst_port, service, sni, None, http_host, tcp_payload)
    }

    fn parse_udp<'a>(&self, payload: &'a [u8]) -> (&'static str, u16, u16, String, Option<String>, Option<String>, Option<String>, &'a [u8]) {
        if payload.len() < 8 {
            return ("UDP", 0, 0, "UDP".to_string(), None, None, None, &[]);
        }
        
        let src_port = u16::from_be_bytes([payload[0], payload[1]]);
        let dst_port = u16::from_be_bytes([payload[2], payload[3]]);
        let udp_payload = if payload.len() > 8 { &payload[8..] } else { &[] };
        
        let service = self.port_to_service(dst_port, src_port);
        let dns_query = if dst_port == 53 || src_port == 53 {
            self.extract_dns_query(udp_payload)
        } else { None };
        
        // QUIC/HTTP3 detection (UDP 443)
        let sni = if dst_port == 443 || src_port == 443 {
            self.extract_quic_sni(udp_payload)
        } else { None };
        
        ("UDP", src_port, dst_port, service, sni, dns_query, None, udp_payload)
    }

    fn extract_http_host(&self, payload: &[u8]) -> Option<String> {
        if payload.len() < 16 { return None; }
        
        // Check for HTTP methods
        let methods = [b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"PATC", b"OPTI", b"CONN"];
        let starts_with_method = methods.iter().any(|m| payload.starts_with(*m));
        if !starts_with_method { return None; }
        
        // Parse HTTP headers to find Host:
        let text = String::from_utf8_lossy(payload);
        for line in text.lines() {
            let lower = line.to_lowercase();
            if lower.starts_with("host:") {
                let host = line[5..].trim();
                // Remove port if present
                let host = host.split(':').next().unwrap_or(host);
                return Some(host.to_string());
            }
        }
        None
    }

    fn extract_quic_sni(&self, payload: &[u8]) -> Option<String> {
        // QUIC Initial packets contain TLS ClientHello in crypto frames
        // This is complex but we can do basic pattern matching
        if payload.len() < 50 { return None; }
        
        // QUIC long header starts with 1xxxxxxx, version, then payload
        if payload[0] & 0x80 == 0 { return None; } // Not long header
        
        // Search for SNI pattern in the payload (0x00 0x00 followed by length and ASCII)
        // This is a heuristic approach
        for i in 0..payload.len().saturating_sub(50) {
            if payload[i] == 0x00 && payload[i+1] == 0x00 && i + 4 < payload.len() {
                let len = u16::from_be_bytes([payload[i+2], payload[i+3]]) as usize;
                if len > 3 && len < 256 && i + 4 + len <= payload.len() {
                    let potential = &payload[i+4..i+4+len];
                    if potential.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-') {
                        if let Ok(domain) = std::str::from_utf8(potential) {
                            if domain.contains('.') && !domain.starts_with('.') {
                                return Some(domain.to_string());
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn port_to_service(&self, dst_port: u16, src_port: u16) -> String {
        let port = if dst_port < 1024 { dst_port } else if src_port < 1024 { src_port } else { dst_port };
        match port {
            20 | 21 => "FTP".to_string(),
            22 => "SSH".to_string(),
            23 => "Telnet".to_string(),
            25 | 587 | 465 => "SMTP".to_string(),
            53 => "DNS".to_string(),
            67 | 68 => "DHCP".to_string(),
            80 | 8080 | 8000 => "HTTP".to_string(),
            110 => "POP3".to_string(),
            123 => "NTP".to_string(),
            143 => "IMAP".to_string(),
            443 | 8443 => "HTTPS".to_string(),
            445 => "SMB".to_string(),
            993 => "IMAPS".to_string(),
            995 => "POP3S".to_string(),
            1080 => "SOCKS".to_string(),
            1433 => "MSSQL".to_string(),
            1723 => "PPTP".to_string(),
            3306 => "MySQL".to_string(),
            3389 => "RDP".to_string(),
            5060 | 5061 => "SIP".to_string(),
            5432 => "PostgreSQL".to_string(),
            5900..=5903 => "VNC".to_string(),
            6379 => "Redis".to_string(),
            27017 => "MongoDB".to_string(),
            _ => format!("Port-{}", dst_port),
        }
    }

    fn extract_tls_sni(&self, payload: &[u8]) -> Option<String> {
        if payload.len() < 43 { return None; }
        if payload[0] != 0x16 { return None; }
        if payload.len() < 6 { return None; }
        if payload[5] != 0x01 { return None; }
        
        let session_id_len = *payload.get(43)? as usize;
        let pos = 44 + session_id_len;
        if payload.len() < pos + 2 { return None; }
        
        let cipher_suites_len = u16::from_be_bytes([payload[pos], payload[pos+1]]) as usize;
        let pos = pos + 2 + cipher_suites_len;
        if payload.len() < pos + 1 { return None; }
        
        let compression_methods_len = payload[pos] as usize;
        let pos = pos + 1 + compression_methods_len;
        if payload.len() < pos + 2 { return None; }
        
        let extensions_len = u16::from_be_bytes([payload[pos], payload[pos+1]]) as usize;
        let mut ext_pos = pos + 2;
        let ext_end = ext_pos + extensions_len;
        
        while ext_pos + 4 < ext_end && ext_pos + 4 < payload.len() {
            let ext_type = u16::from_be_bytes([payload[ext_pos], payload[ext_pos+1]]);
            let ext_len = u16::from_be_bytes([payload[ext_pos+2], payload[ext_pos+3]]) as usize;
            
            if ext_type == 0 {
                if payload.len() >= ext_pos + 9 + ext_len {
                    let name_len = u16::from_be_bytes([payload[ext_pos+7], payload[ext_pos+8]]) as usize;
                    if payload.len() >= ext_pos + 9 + name_len {
                        let sni = String::from_utf8_lossy(&payload[ext_pos+9..ext_pos+9+name_len]).to_string();
                        return Some(sni);
                    }
                }
            }
            ext_pos += 4 + ext_len;
        }
        None
    }

    fn extract_dns_query(&self, payload: &[u8]) -> Option<String> {
        if payload.len() < 12 { return None; }
        let mut pos = 12;
        let mut domain_parts = Vec::new();
        
        while pos < payload.len() {
            let len = payload[pos] as usize;
            if len == 0 { break; }
            if pos + 1 + len > payload.len() { break; }
            domain_parts.push(String::from_utf8_lossy(&payload[pos+1..pos+1+len]).to_string());
            pos += 1 + len;
        }
        
        if !domain_parts.is_empty() {
            Some(domain_parts.join("."))
        } else {
            None
        }
    }

    fn identify_application(&self, dst_ip: &str, _dst_port: u16, domain: Option<&str>) -> Option<String> {
        let domain = domain?;
        let d = domain.to_lowercase();
        
        if d.contains("google") || d.contains("gstatic") || d.contains("googleapis") || d.contains("gvt1") || d.contains("gvt2") { return Some("Google".into()); }
        if d.contains("youtube") || d.contains("ytimg") || d.contains("googlevideo") || d.contains("youtu.be") { return Some("YouTube".into()); }
        if d.contains("netflix") || d.contains("nflx") { return Some("Netflix".into()); }
        if d.contains("facebook") || d.contains("fbcdn") || d.contains("fb.com") || d.contains("fbsbx") { return Some("Facebook".into()); }
        if d.contains("instagram") || d.contains("cdninstagram") { return Some("Instagram".into()); }
        if d.contains("twitter") || d.contains("twimg") || d.contains("x.com") || d.contains("t.co") { return Some("Twitter/X".into()); }
        if d.contains("microsoft") || d.contains("windows") || d.contains("msn.com") || d.contains("azure") || d.contains("bing.") || d.contains("office") || d.contains("live.com") || d.contains("sharepoint") || d.contains("onedrive") { return Some("Microsoft".into()); }
        if d.contains("apple") || d.contains("icloud") || d.contains("itunes") { return Some("Apple".into()); }
        if d.contains("amazon") || d.contains("aws") || d.contains("prime") { return Some("Amazon".into()); }
        if d.contains("spotify") || d.contains("scdn") { return Some("Spotify".into()); }
        if d.contains("discord") { return Some("Discord".into()); }
        if d.contains("steam") || d.contains("valve") || d.contains("steampowered") { return Some("Steam".into()); }
        if d.contains("cloudflare") { return Some("Cloudflare".into()); }
        if d.contains("akamai") { return Some("Akamai CDN".into()); }
        if d.contains("fastly") { return Some("Fastly CDN".into()); }
        if d.contains("tiktok") || d.contains("bytedance") || d.contains("ttoast") { return Some("TikTok".into()); }
        if d.contains("whatsapp") { return Some("WhatsApp".into()); }
        if d.contains("zoom") || d.contains("zoomgov") { return Some("Zoom".into()); }
        if d.contains("telegram") || d.contains("t.me") { return Some("Telegram".into()); }
        if d.contains("twitch") || d.contains("jtvnw") { return Some("Twitch".into()); }
        if d.contains("reddit") { return Some("Reddit".into()); }
        if d.contains("pornhub") || d.contains("phncdn") { return Some("Pornhub".into()); }
        if d.contains("xvideos") { return Some("XVideos".into()); }
        if d.contains("xhamster") { return Some("xHamster".into()); }
        if d.contains("openai") || d.contains("chatgpt") { return Some("OpenAI".into()); }
        if d.contains("github") { return Some("GitHub".into()); }
        if d.contains("gitlab") { return Some("GitLab".into()); }
        if d.contains("stackoverflow") { return Some("StackOverflow".into()); }
        
        None
    }

    fn categorize_traffic(&self, service: &str, _port: u16, application: Option<&str>) -> String {
        if let Some(app) = application {
            match app {
                "YouTube" | "Netflix" | "Spotify" | "TikTok" | "Twitch" => return "Media".into(),
                "Facebook" | "Instagram" | "Twitter/X" | "Discord" | "WhatsApp" | "Telegram" | "Reddit" => return "Social".into(),
                "Steam" => return "Gaming".into(),
                "Microsoft" | "Apple" | "Google" | "Cloudflare" | "Akamai CDN" | "Fastly CDN" => return "System/Cloud".into(),
                "Zoom" => return "Communication".into(),
                "Pornhub" | "XVideos" | "xHamster" => return "Adult".into(),
                "OpenAI" | "GitHub" | "GitLab" | "StackOverflow" => return "Development".into(),
                _ => {}
            }
        }
        
        match service {
            "HTTP" | "HTTPS" => "Web".into(),
            "DNS" | "DHCP" | "NTP" | "ICMP" | "IGMP" => "System".into(),
            "SSH" | "RDP" | "VNC" | "Telnet" => "Remote Access".into(),
            "SMTP" | "IMAP" | "POP3" | "IMAPS" | "POP3S" => "Email".into(),
            "SMB" | "FTP" => "File Transfer".into(),
            "MySQL" | "PostgreSQL" | "MongoDB" | "Redis" | "MSSQL" => "Database".into(),
            "SIP" => "VoIP".into(),
            _ => "Unknown".into(),
        }
    }

    fn generate_insight(&self, dst: &str, service: &str, category: &str, app: Option<&str>, domain: Option<&str>) -> String {
        let target = app.or(domain).unwrap_or(dst);
        
        match category {
            "Media" => format!("🎬 Streaming: {}", target),
            "Social" => format!("💬 Social: {}", target),
            "Gaming" => format!("🎮 Gaming: {}", target),
            "Web" => format!("🌐 {} → {}", service, target),
            "System" | "System/Cloud" => format!("⚙️ System: {}", target),
            "Remote Access" => format!("⚠️ Remote: {} → {}", service, dst),
            "Email" => format!("📧 Email via {}", service),
            "Database" => format!("⚠️ Database: {} → {}", service, dst),
            "VoIP" => format!("📞 Voice/Video"),
            "Communication" => format!("📹 Conference: {}", target),
            "Adult" => format!("🔞 Adult: {}", target),
            "Development" => format!("💻 Dev: {}", target),
            _ => format!("{} → {}", service, target),
        }
    }
}

fn now_unix() -> u64 {
    SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs()
}
