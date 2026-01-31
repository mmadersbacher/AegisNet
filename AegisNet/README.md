# AegisNet 🛡️

Ein moderner Network Scanner mit Deep Packet Inspection - gebaut aus Neugier und dem Wunsch zu verstehen, was eigentlich in meinem Netzwerk so abgeht.

## Was ist das hier?

AegisNet ist ein Network Scanner den ich gebaut habe um mein lokales Netzwerk zu analysieren. Keine fancy Enterprise-Lösung, sondern ein Tool das tut was ich brauche:

- **Geräte im Netzwerk finden** - Wer hängt alles an meinem Router?
- **Live Traffic analysieren** - Welche Verbindungen laufen gerade?
- **Deep Packet Inspection** - Wohin geht der Traffic? Netflix? YouTube? Oder doch was anderes?

## Features

### 🔍 Device Discovery
- ARP Scanning für schnelle Geräteerkennung
- mDNS/Bonjour für Apple-Geräte
- SSDP für Smart Home & UPnP Devices
- NetBIOS für Windows-Kisten
- MAC-Vendor Lookup (wer hat das Gerät gebaut?)

### 📡 Traffic Analysis (Deep Packet Inspection)
Das Herzstück. Ich wollte wissen was in meinem Netzwerk passiert:

- **TLS SNI Extraction** - Sieht welche Domains bei HTTPS angefragt werden
- **DNS Query Tracking** - Jede DNS-Anfrage wird mitgeschnitten
- **HTTP Host Header** - Bei unverschlüsseltem Traffic
- **IP Range Database** - 100+ bekannte IP-Bereiche (Google, Netflix, Facebook, Steam, etc.)
- **Reverse DNS Lookups** - Für unbekannte IPs
- **QUIC/HTTP3 Support** - Auch moderner Traffic wird erkannt

### 🏷️ Automatische Kategorisierung
Der Traffic wird automatisch kategorisiert:
- 🎬 Media (YouTube, Netflix, Spotify, Twitch)
- 💬 Social (Facebook, Instagram, Discord, WhatsApp)
- 🎮 Gaming (Steam, Epic, etc.)
- ⚙️ System (Microsoft, Apple, Google Cloud)
- 🔞 Adult (ja, auch das wird erkannt)
- 💻 Development (GitHub, StackOverflow)

### 🔎 Filtering
Einfach nach IP, Domain, App oder Kategorie filtern. Suche nach "youtube" und sieh allen YouTube-Traffic.

## Tech Stack

**Backend (Rust)**
- Axum für die REST API
- Raw Sockets für Packet Capture
- SeaORM + SQLite für Persistenz
- Tokio async runtime

**Frontend (React + TypeScript)**
- Vite als Build Tool
- TailwindCSS für Styling
- Lucide Icons

## Setup

### Voraussetzungen
- Rust (stable)
- Node.js 18+
- Windows (für Raw Socket Support - Linux theoretisch möglich aber nicht getestet)
- **Admin-Rechte** (für Raw Socket Zugriff)

### Installation

```bash
# Repository clonen
git clone https://github.com/mmadersbacher/AegisNet.git
cd AegisNet

# Backend starten (ALS ADMINISTRATOR!)
cd backend
cargo run

# In neuem Terminal: Frontend starten
cd frontend
npm install
npm run dev
```

**Wichtig:** Das Backend MUSS als Administrator laufen! Raw Sockets brauchen erhöhte Rechte. Sonst bekommst du `Error 10013: Permission denied`.

### Zugriff
- Frontend: http://localhost:5173
- Backend API: http://localhost:8000

## Wie funktioniert die DPI?

1. **Passive DNS Cache** - Jede DNS-Anfrage wird gespeichert. Wenn später eine TCP-Verbindung zu einer IP geht, weiß ich welche Domain dahinter steckt.

2. **TLS SNI Parsing** - Bei HTTPS wird die Server Name Indication aus dem ClientHello extrahiert.

3. **IP Range Matching** - Über 100 IP-Bereiche von großen Providern sind hinterlegt. Verbindung zu 142.250.x.x? Das ist Google.

4. **Reverse DNS** - Als Fallback wird ein Reverse-DNS Lookup gemacht.

5. **Application Patterns** - 35+ Patterns für bekannte Services (Netflix, Spotify, Discord, etc.)

## Limitationen

- **TLS 1.3 mit ECH** - Encrypted Client Hello versteckt die SNI. Da kann ich nichts machen.
- **VPNs** - Wenn alles durch einen VPN-Tunnel geht, sehe ich nur die VPN-IP.
- **Nur IPv4** - IPv6 Support ist nicht implementiert.

## Disclaimer

Das ist ein Hobby-Projekt. Nutze es nur in deinem eigenen Netzwerk. Fremden Traffic mitzuschneiden ist illegal.

## Lizenz

MIT - Mach damit was du willst.

---

*Gebaut mit viel ☕ und dem Wunsch zu verstehen wie Netzwerke funktionieren.*
