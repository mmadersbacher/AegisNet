pub struct OsFingerprint;

impl OsFingerprint {
    pub fn infer(ttl: u8, open_ports: &[u16]) -> String {
        let mut os = String::from("Unknown OS");

        if ttl <= 64 {
            os = String::from("Linux / macOS / iOS");
            if open_ports.contains(&548) { os = String::from("macOS (AFP)"); }
            if open_ports.contains(&22) && !open_ports.contains(&445) { os = String::from("Linux Server"); }
            if open_ports.contains(&62078) { os = String::from("iOS Device"); }
        } else if ttl <= 128 {
            os = String::from("Windows");
            if open_ports.contains(&445) || open_ports.contains(&135) { os = String::from("Windows PC"); }
        } else {
             os = String::from("Network Appliance (Cisco/Solaris)");
        }
        
        return os;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_inference() {
        let ports = vec![22, 80];
        assert_eq!(OsFingerprint::infer(64, &ports), "Linux Server");
    }

    #[test]
    fn test_windows_inference() {
        let ports = vec![135, 445];
        assert_eq!(OsFingerprint::infer(128, &ports), "Windows PC");
    }
    
    #[test]
    fn test_ios_inference() {
        let ports = vec![62078];
        assert_eq!(OsFingerprint::infer(64, &ports), "iOS Device");
    }

    #[test]
    fn test_unknown_ttl() {
        assert_eq!(OsFingerprint::infer(255, &[]), "Network Appliance (Cisco/Solaris)");
    }
}
