pub struct OuiDb;

impl OuiDb {
    pub fn lookup(mac: &str) -> String {
        let clean = mac.replace(":", "").replace("-", "").to_uppercase();
        if clean.len() < 6 { return "Unknown".to_string(); }
        let prefix = &clean[0..6];

        match prefix {
            // APPLE
            "0017F2" | "0019E3" | "001B63" | "001C27" | "001D4F" | "001E52" | "001F5B" | "001F5C" |
            "0021E9" | "002241" | "002312" | "002332" | "00236C" | "0023DF" | "002436" | "002500" |
            "00254B" | "0025BC" | "002608" | "00264A" | "0026B0" | "0026BB" | "080007" | "086D41" |
            "0050E4" | "040CCE" | "041557" | "041E64" | "042665" | "04489A" | "045453" | "0469F8" |
            "000000" | "000393" | "000502" | "000A27" | "000A95" | "000D93" | "0010FA" | "001124" |
            "BC5C4C" | "F01898" | "7C6DF8" | "FE5F01" | "24F6FA" | "5855CA" | "40D32D" | "A4D1D2" => "Apple, Inc.".to_string(),
            
            // SAMSUNG
            "001247" | "001599" | "001632" | "0017C9" | "0018AF" | "001A83" | "001D25" | "001E7D" |
            "847E40" | "147590" | "1867B0" | "1C5A3E" | "24F5AA" | "28987B" | "2C683D" | "30074D" => "Samsung Electronics".to_string(),
            
            // IOT & SMART HOME
            "240AC4" | "ECFABC" | "2462AB" | "246F28" | "24A160" | "24B2DE" | "2C3AE8" | "30AEA4" | 
            "3C6105" | "3C71BF" | "483FDA" | "485519" | "4C11AE" | "4C7525" | "500291" | "543204" => "Espressif (Smart Home/IoT)".to_string(),
            "B827EB" | "DCA632" | "E45F01" | "D83ADD" => "Raspberry Pi Foundation".to_string(),
            "001788" | "0024E4" => "Philips Lighting (Hue)".to_string(),
            "50C7BF" | "70886B" => "TP-Link (Smart Plug)".to_string(),
            
            // NETWORKING
            "7483C2" | "F09FC2" | "00156D" | "002722" | "0418D6" | "089CDE" | "0C1A3F" | "18E829" |
            "245A4C" | "24A43C" | "44D9E7" | "602232" | "68D79A" | "70A741" | "784558" | "788A20" => "Ubiquiti Networks".to_string(),
            "001478" | "0016D4" | "0019E0" | "001F33" | "0026F2" | "149182" | "180F76" | "1C4024" => "TP-Link (Router)".to_string(),
            "00095B" | "000F66" | "00146C" | "00184D" | "001B2F" | "001E2A" | "00223F" | "0024B2" => "Netgear".to_string(),
            "00000C" | "000142" | "000143" | "000163" | "000164" | "000196" | "000197" | "0001C7" |
            "0001C9" | "0001E3" | "00508B" | "006009" | "00602F" | "006047" => "Cisco Systems".to_string(),
            "001132" | "001111" | "00152C" | "001C10" => "Synology (NAS)".to_string(),
            "000C29" | "005056" | "000569" => "VMware (Virtual)".to_string(),
            "00155D" | "0003FF" => "Microsoft Hyper-V".to_string(),
            
            // PC & CHIPS
            "00A0C9" | "0002B3" | "000347" | "0004AC" | "0007E9" | "000C86" | "000C8B" | "000E0C" => "Intel Corporate".to_string(),
            "0050B6" | "000476" | "001282" | "002242" | "00241D" | "002522" | "00045A" => "Linksys".to_string(),
            "000420" | "00065B" | "000802" | "000B02" | "000D56" | "000F20" | "001018" | "001422" => "Dell".to_string(),
            
            _ => "Unknown Vendor".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apple_oui() {
        assert_eq!(OuiDb::lookup("00:17:F2:00:00:00"), "Apple, Inc.");
    }

    #[test]
    fn test_samsung_oui() {
        assert_eq!(OuiDb::lookup("00-12-47-11-22-33"), "Samsung Electronics");
    }

    #[test]
    fn test_unknown_oui() {
        assert_eq!(OuiDb::lookup("FF:FF:FF:00:00:00"), "Unknown Vendor");
    }
    
    #[test]
    fn test_malformed_input() {
        assert_eq!(OuiDb::lookup("123"), "Unknown");
    }
}
