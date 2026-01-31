pub mod discovery;
pub mod fingerprint;
pub mod traffic;
pub mod vuln;
pub mod core;

use serde::Serialize;

#[derive(Serialize, Clone, Debug)]
pub struct Host {
    pub ip: String,
    pub mac: String,
    pub hostname: String,
    pub vendor: String,
    pub manufacturer: Option<String>, // e.g. "Apple Inc.", "Samsung Electronics"
    pub model: Option<String>,        // e.g. "MacBookPro18,3", "UE55NU7179"
    pub friendly_name: Option<String>, // e.g. "Living Room TV", "Dave's iPhone"
    pub os_family: String, // Windows, Linux, MacOS, iOS, Android
    pub device_type: String, // Server, Desktop, Phone, IoT, Router
    pub open_ports: Vec<u16>,
    pub services: Vec<Service>,
    pub risk_score: u8,
}

#[derive(Serialize, Clone, Debug)]
pub struct Service {
    pub port: u16,
    pub protocol: String, // TCP/UDP
    pub name: String, // ssh, http
    pub banner: String, // "OpenSSH 8.2p1"
    pub version: String,
    pub cves: Vec<String>,
}

pub trait ScannerModule {
    fn name(&self) -> &'static str;
}
