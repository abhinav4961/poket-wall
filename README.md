# Pocket-Wall

A lightweight proxy-based firewall with AI-powered intrusion detection, built in Python for Raspberry Pi Zero 2 W.

## Features

- **Proxy Server** — HTTP & HTTPS (CONNECT) traffic filtering on port 3128
- **Domain Blocklisting** — StevenBlack + URLHaus blocklists with custom rules, parent domain matching
- **IDS Engine** — AbuseIPDB threat intelligence + geo-blocking + nftables/iptables IP blocking
- **AI Behavioral Analysis** — Pre-trained Isolation Forest detects anomaly patterns (batch mode, runs every 60s)
- **Deep Packet Inspection** — Detects SQLi, XSS, path traversal, command injection (inspection.py)
- **Port Scan Detection** — Blocks IPs probing multiple ports in a short time window
- **Brute Force Detection** — Blocks IPs with repeated errors (e.g., failed auth attempts)
- **Honeypot Module** — Fake endpoints that auto-block any IP that touches them
- **Flood Protection** — Per-IP rate limiting with automatic ban windows
- **REST API** — Full dashboard API on port 5000 with stats, events, alerts, and management endpoints
- **TUI Dashboard** — Terminal-based monitoring interface
- **Zero Dependencies** — Pure Python standard library only (no pip installs needed on the Pi)
- **Persistent Blocks** — Blocked IPs survive restarts via JSON storage

## Quick Start

```bash
cd firewall
python3 main.py
```

Set your device proxy to `<pi-ip>:3128`

## Command Options

```bash
python3 main.py                    # Run proxy (default)
python3 main.py --tui              # Launch with TUI dashboard
python3 main.py --web              # Launch with REST API on port 5000
python3 main.py --no-ids           # Disable IDS engine
python3 main.py --test-ids 1.1.1.1 # Test AbuseIPDB API and exit
```

## Configuration

### Custom Blocklist (`rules.json`)
Add domains to block:
```json
{
  "blacklist": [
    "facebook.com",
    "doubleclick.net"
  ]
}
```

### Geo-Blocking (`geo_rules.json`)
Configure blocked countries and threat score thresholds:
```json
{
  "blocked_countries": ["CN", "RU"],
  "score_threshold_block": 75,
  "score_threshold_warn": 40
}
```

### API Key (`.env`)
Set your AbuseIPDB API key:
```
abuse_ipdb_api_key=YOUR_KEY_HERE
```

## Architecture

```
Client ──▶ Proxy (main.py) ──▶ Blocklist Check (firewall.py) ──▶ Forward Traffic
                                      │
                                      └──▶ Background IDS (ids.py)
                                            ├── AbuseIPDB reputation
                                            ├── Geo-blocking
                                            ├── Port Scan Detection
                                            ├── Brute Force Detection
                                            ├── Honeypot Module
                                            └── AI anomaly detection (ai_model.py)
```

### How the AI Works

The AI runs as a **batch log analyzer**, not per-connection. Every 60 seconds it:
1. Collects behavioral features from all active IPs (connection rate, unique ports, error rate, special characters, etc.)
2. Scores each IP using a pre-trained Isolation Forest model
3. Generates alerts for IPs above the anomaly threshold
4. Auto-adapts its baseline based on your network's normal traffic patterns

The model is pre-trained on synthetic normal and attack traffic. No training needed on the Pi.

### Retraining the Model

On a development machine:
```bash
cd firewall
pip install scikit-learn
python3 train_model.py
```
This generates a new `ai_model.json` you can deploy to the Pi.

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/stats` | GET | IDS statistics |
| `/api/events` | GET | Recent IDS events |
| `/api/alerts` | GET | Active alerts |
| `/api/ai-stats` | GET | AI model status and baseline |
| `/api/ai-ip?ip=X` | GET | Per-IP AI analysis details |
| `/api/dpi-stats` | GET | Deep Packet Inspection stats |
| `/api/port-scan-stats` | GET | Port scan detection stats |
| `/api/brute-force-stats` | GET | Brute force detection stats |
| `/api/honeypot-stats` | GET | Honeypot module stats |
| `/api/rules` | GET/POST | Manage custom blocklist |
| `/api/geo` | GET/POST | Manage geo-blocking config |
| `/api/blocked-ips` | GET | List blocked IPs |
| `/api/unblock` | POST | Unblock an IP |
| `/api/logs` | GET | View proxy logs |
| `/api/flood-status` | GET | Current flood protection state |
| `/api/check-domain` | POST | Check if a domain is blocked |
| `/api/clear-port-scan` | POST | Clear port scan tracker |
| `/api/clear-brute-force` | POST | Clear brute force tracker |
| `/api/honeypot/add` | POST | Add honeypot path |
| `/api/honeypot/remove` | POST | Remove honeypot path |

## File Structure

```
poket-wall/
├── firewall/
│   ├── main.py           # Proxy server + HTTP forwarding
│   ├── firewall.py       # Blocklist + domain filtering + flood protection
│   ├── ids.py            # AbuseIPDB + IP blocking + AI integration
│   ├── ai_model.py       # Feature extraction + Isolation Forest + batch analysis
│   ├── api.py            # REST API server
│   ├── tui.py            # Terminal UI dashboard
│   ├── train_model.py    # AI model training script (dev machine)
│   ├── ai_model.json     # Pre-trained model
│   ├── .env              # AbuseIPDB API key
│   ├── rules.json        # Custom blocklist
│   ├── geo_rules.json    # Geo-blocking config
│   ├── blocked_ips.json  # Persistent blocks (auto-generated)
│   ├── logs/             # Proxy logs
│   └── blocklist_cache/  # Cached blocklists
├── README.md
└── .gitignore
```

## Resource Usage

| Metric | Value |
|--------|-------|
| RAM | ~50MB |
| CPU | Near idle (< 1ms per AI inference) |
| Model size | ~48KB |
| Dependencies | Python 3.10+ only |
