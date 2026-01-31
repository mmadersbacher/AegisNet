use dashmap::DashMap;
use std::sync::OnceLock;
use std::path::Path;
use tokio::fs;
use tokio::io::AsyncWriteExt;

// Global OUI Database
static OUI_CACHE: OnceLock<DashMap<String, String>> = OnceLock::new();

pub struct OuiLive;

impl OuiLive {
    pub fn get_db() -> &'static DashMap<String, String> {
        OUI_CACHE.get_or_init(|| DashMap::new())
    }

    pub fn lookup(mac: &str) -> Option<String> {
        let clean = mac.replace(":", "").replace("-", "").to_uppercase();
        if clean.len() < 6 { return None; }
        let prefix = &clean[0..6];
        
        if let Some(vendor) = Self::get_db().get(prefix) {
            return Some(vendor.clone());
        }
        None
    }

    pub async fn init() {
        let db = Self::get_db();
        let path = Path::new("oui.txt");

        // 1. Check if file exists, if not download
        if !path.exists() {
            tracing::info!("OUI Database not found. Downloading from IEEE...");
            if let Err(e) = Self::download_ieee_export(path).await {
                tracing::error!("Failed to download OUI database: {}", e);
                return;
            }
            tracing::info!("OUI Database downloaded successfully.");
        }

        // 2. Load into memory
        tracing::info!("Loading OUI Database into memory...");
        if let Ok(contents) = fs::read_to_string(path).await {
            for line in contents.lines() {
                // Format: 00-00-00   (hex)		XEROX CORPORATION
                if line.contains("(hex)") {
                    let parts: Vec<&str> = line.split("(hex)").collect();
                    if parts.len() >= 2 {
                        let mac_part = parts[0].trim().replace("-", "");
                        let vendor_part = parts[1].trim();
                        if mac_part.len() == 6 {
                            db.insert(mac_part, vendor_part.to_string());
                        }
                    }
                }
            }
            tracing::info!("Loaded {} OUI records.", db.len());
        }
    }

    async fn download_ieee_export(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let url = "http://standards-oui.ieee.org/oui/oui.txt";
        let response = reqwest::get(url).await?;
        let content = response.text().await?;
        
        let mut file = fs::File::create(path).await?;
        file.write_all(content.as_bytes()).await?;
        Ok(())
    }
}
