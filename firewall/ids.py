"""
IDS Engine — AbuseIPDB integration + threat scoring + iptables blocking.
"""

import ipaddress
import json
import os
import subprocess
import time
import urllib.request
import urllib.error
from collections import deque
from dataclasses import dataclass, field
from threading import Lock

# --------------- data structures ---------------

@dataclass
class IDSEvent:
    timestamp: float
    ip: str
    score: int
    country: str
    isp: str
    action: str          # "BLOCK", "WARN", "ALLOW"
    reason: str
    total_reports: int = 0
    is_tor: bool = False


@dataclass
class IDSStats:
    total: int = 0
    blocked: int = 0
    warned: int = 0
    allowed: int = 0


# --------------- AbuseIPDB checker ---------------

class AbuseIPDBChecker:
    """Queries AbuseIPDB /check endpoint with caching."""

    API_URL = "https://api.abuseipdb.com/api/v2/check"
    CACHE_TTL = 3600  # 1 hour

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._cache: dict[str, tuple[float, dict]] = {}
        self._lock = Lock()

    def check(self, ip: str) -> dict | None:
        """
        Returns dict with keys:
          confidence_score, country_code, isp, total_reports, is_tor
        Returns None on error / private IP.
        """
        # Skip private / loopback
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return None
        except ValueError:
            return None

        # Check cache
        with self._lock:
            if ip in self._cache:
                ts, data = self._cache[ip]
                if time.time() - ts < self.CACHE_TTL:
                    return data

        # Query API
        try:
            url = f"{self.API_URL}?ipAddress={ip}&maxAgeInDays=90&verbose"
            req = urllib.request.Request(url)
            req.add_header("Key", self.api_key)
            req.add_header("Accept", "application/json")

            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode())

            d = body.get("data", {})
            result = {
                "confidence_score": d.get("abuseConfidenceScore", 0),
                "country_code": d.get("countryCode", "??"),
                "isp": d.get("isp", "Unknown"),
                "total_reports": d.get("totalReports", 0),
                "is_tor": d.get("isTor", False),
            }

            with self._lock:
                self._cache[ip] = (time.time(), result)

            return result

        except Exception:
            return None


# --------------- IDS engine ---------------

class IDSEngine:
    """Central IDS decision-maker. Thread-safe."""

    def __init__(self, api_key: str, config_path: str = "geo_rules.json"):
        self.checker = AbuseIPDBChecker(api_key)
        self.config_path = config_path
        self._lock = Lock()

        # Events ring buffer for TUI
        self.events: deque[IDSEvent] = deque(maxlen=500)
        self.alerts: deque[IDSEvent] = deque(maxlen=200)
        self.stats = IDSStats()

        # Blocked IPs set (iptables)
        self._blocked_ips: set[str] = set()

        # Load config
        self.blocked_countries: set[str] = set()
        self.threshold_block = 75
        self.threshold_warn = 40
        self._load_config()

    # ---------- config ----------

    def _load_config(self):
        try:
            with open(self.config_path) as f:
                cfg = json.load(f)
            self.blocked_countries = set(
                c.upper() for c in cfg.get("blocked_countries", [])
            )
            self.threshold_block = cfg.get("score_threshold_block", 75)
            self.threshold_warn = cfg.get("score_threshold_warn", 40)
        except Exception:
            pass

    def save_config(self):
        try:
            cfg = {
                "blocked_countries": sorted(self.blocked_countries),
                "score_threshold_block": self.threshold_block,
                "score_threshold_warn": self.threshold_warn,
            }
            with open(self.config_path, "w") as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass

    # ---------- geo-block management ----------

    def add_country(self, code: str):
        self.blocked_countries.add(code.upper())
        self.save_config()

    def remove_country(self, code: str):
        self.blocked_countries.discard(code.upper())
        self.save_config()

    # ---------- core check ----------

    def check_ip(self, ip: str) -> str:
        """
        Check an IP. Returns "BLOCK", "WARN", or "ALLOW".
        Creates an IDSEvent and appends it to the queues.
        """
        # Already blocked at iptables level
        if ip in self._blocked_ips:
            return "BLOCK"

        result = self.checker.check(ip)

        if result is None:
            # Private IP or API error — allow
            ev = IDSEvent(
                timestamp=time.time(),
                ip=ip,
                score=0,
                country="LAN",
                isp="Local",
                action="ALLOW",
                reason="Private/local IP",
            )
            self._record(ev)
            return "ALLOW"

        score = result["confidence_score"]
        country = result["country_code"]
        isp = result["isp"]
        total_reports = result["total_reports"]
        is_tor = result["is_tor"]

        # Determine action
        action = "ALLOW"
        reason = ""

        # Geo-block check
        if country in self.blocked_countries:
            action = "BLOCK"
            reason = f"Geo-blocked country: {country}"
        # Score check
        elif score >= self.threshold_block:
            action = "BLOCK"
            reason = f"High threat score: {score}%"
        elif score >= self.threshold_warn:
            action = "WARN"
            reason = f"Moderate threat score: {score}%"
        elif is_tor:
            action = "WARN"
            reason = "TOR exit node"
        else:
            reason = "Clean"

        ev = IDSEvent(
            timestamp=time.time(),
            ip=ip,
            score=score,
            country=country,
            isp=isp,
            action=action,
            reason=reason,
            total_reports=total_reports,
            is_tor=is_tor,
        )

        # Apply block
        if action == "BLOCK":
            self._iptables_block(ip)

        self._record(ev)
        return action

    # ---------- internal ----------

    def _record(self, ev: IDSEvent):
        with self._lock:
            self.events.append(ev)
            self.stats.total += 1
            if ev.action == "BLOCK":
                self.stats.blocked += 1
                self.alerts.append(ev)
            elif ev.action == "WARN":
                self.stats.warned += 1
                self.alerts.append(ev)
            else:
                self.stats.allowed += 1

    def _iptables_block(self, ip: str):
        if ip in self._blocked_ips:
            return
        try:
            subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                timeout=5,
                capture_output=True,
            )
            self._blocked_ips.add(ip)
        except Exception:
            pass  # might not have root

    def unblock_ip(self, ip: str):
        if ip not in self._blocked_ips:
            return
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                timeout=5,
                capture_output=True,
            )
            self._blocked_ips.discard(ip)
        except Exception:
            pass

    def get_blocked_ips(self) -> list[str]:
        return sorted(self._blocked_ips)

    def clear_alerts(self):
        with self._lock:
            self.alerts.clear()


# --------------- env loader ---------------

def load_api_key(env_path: str = ".env") -> str:
    """Parse the .env file for abuse_ipdb_api_key."""
    try:
        with open(env_path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                if key.strip() == "abuse_ipdb_api_key":
                    return val.strip()
    except Exception:
        pass
    return ""
