use tokio::net::UdpSocket;
use std::time::Duration;
use std::collections::HashMap;

pub struct SnmpData {
    pub sys_descr: String,
}

pub async fn fingerprint(ip: &str) -> Option<SnmpData> {
    let target = format!("{}:161", ip);
    let socket = UdpSocket::bind("0.0.0.0:0").await.ok()?;
    
    // SNMP v2c GetRequest, Community "public", OID 1.3.6.1.2.1.1.1.0 (sysDescr)
    // Manually constructed BER/ASN.1 packet
    // Sequence {
    //   version: 1 (v2c),
    //   community: "public",
    //   pdu: GetRequest { ... }
    // }
    let packet: [u8; 43] = [
        0x30, 0x29, // SEQUENCE, len 41
        0x02, 0x01, 0x01, // INTEGER 1 (Version 2c)
        0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, // OCTET STRING "public"
        0xA0, 0x1C, // GetRequest-PDU, len 28
        0x02, 0x04, 0x12, 0x34, 0x56, 0x78, // Request-ID
        0x02, 0x01, 0x00, // Error 0
        0x02, 0x01, 0x00, // Error Index 0
        0x30, 0x0E, // VarBindList, len 14
        0x30, 0x0C, // VarBind, len 12
        0x06, 0x08, 0x2B, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OBJECT IDENTIFIER 1.3.6.1.2.1.1.1.0 (sysDescr)
        0x05, 0x00  // NULL
    ];

    socket.send_to(&packet, &target).await.ok()?;

    let mut buf = [0u8; 1024];
    if let Ok(Ok((len, _))) = tokio::time::timeout(Duration::from_millis(500), socket.recv_from(&mut buf)).await {
        if len > 0 {
            // Simple string extraction - Look for patterns because parsing ASN.1 in raw rust without crate is hard
            // The sysDescr usually appears at the end of the packet as an Octet String.
            // We search for the "public" string (community) and skip it, then find next big string.
            // Or just sanitize any printable string longest than 5 chars found after the OID.
            // A lazy heuristic:
            let s = String::from_utf8_lossy(&buf[..len]);
            // Remove "public"
            let clean = s.replace("public", "");
            // Find printable ASCII sequence
            let re = regex::Regex::new(r"[a-zA-Z0-9\s\-\._:;,/()]+").unwrap();
            let mut best_match = String::from("SNMP Device");
            for caps in re.captures_iter(&clean) {
                if let Some(m) = caps.get(0) {
                    if m.as_str().len() > 5 {
                        best_match = m.as_str().trim().to_string();
                    }
                }
            }
            return Some(SnmpData { sys_descr: best_match });
        }
    }
    None
}
