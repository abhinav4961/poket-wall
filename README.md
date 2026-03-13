# Pocket-Wall

A lightweight proxy-based firewall written in Python, built to run on a Raspberry Pi Zero 2 W.
Routes network traffic through a local proxy, logging and blocking domains based on a custom ruleset.

## Features

- HTTP & HTTPS traffic filtering
- Domain blacklisting with parent domain matching
- Per-request logging with client IP
- No external dependencies

## Setup

```bash
python main.py
```

Point your device's proxy to `<raspberry-pi-ip>:3128`

## Configuration

Add domains to block in `rules.json`:

```json
{
  "blacklist": [
    "facebook.com",
    "doubleclick.net"
  ]
}
```