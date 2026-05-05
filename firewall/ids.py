"""
IDS Engine — AbuseIPDB + nftables + AI batch analysis.
AI runs as a background log analyzer, not per-connection.
"""

import ipaddress
import json
import logging
import os
import shutil
import subprocess
import time
import urllib.request
import urllib.error
from collections import deque
from dataclasses import dataclass
from threading import Lock

try:
    from ai_model import AIEngine
    AI_AVAILABLE = True
except ImportError as e:
    AI_AVAILABLE = False
    AIEngine = None

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
GEO_RULES_PATH = os.path.join(BASE_DIR, "geo_rules.json")
ENV_PATH = os.path.join(BASE_DIR, ".env")
BLOCKED_IPS_FILE = os.path.join(BASE_DIR, "blocked_ips.json")
CACHE_TTL = 86400

log = logging.getLogger("piwall")


@dataclass
class IDSEvent:
    timestamp: float
    ip: str
    score: int
    country: str
    isp: str
    action: str
    reason: str
    total_reports: int = 0
    is_tor: bool = False


@dataclass
class IDSStats:
    total: int = 0
    blocked: int = 0
    warned: int = 0
    allowed: int = 0


class AbuseIPDBChecker:
    API_URL = "https://api.abuseipdb.com/api/v2/check"
    CACHE_TTL = 3600

    def __init__(self, api_key: str):
        self.api_key = api_key
        self._cache: dict[str, tuple[float, dict]] = {}
        self._lock = Lock()

    def check(self, ip: str) -> dict | None:
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return None
        except ValueError:
            return None

        with self._lock:
            if ip in self._cache:
                ts, data = self._cache[ip]
                if time.time() - ts < self.CACHE_TTL:
                    return data

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

        except urllib.error.HTTPError as e:
            error_body = e.read().decode()
            if e.code == 429:
                log.warning("[IDS] AbuseIPDB rate limited")
            else:
                log.error(f"[IDS] AbuseIPDB HTTP {e.code}: {error_body}")
            return None
        except Exception as e:
            log.error(f"[IDS] AbuseIPDB error: {e}")
            return None


class IPBlocker:
    TABLE_NAME = "pocket_wall"
    SET_NAME = "blocked"

    def __init__(self):
        self._method = None
        self._nft_initialized = False
        self._detect_method()
        if self._method == "nftables":
            self._nft_ensure_set()

    def _detect_method(self):
        if shutil.which("nft") and self._test_nftables():
            self._method = "nftables"
        elif shutil.which("iptables") and self._test_iptables():
            self._method = "iptables"
        else:
            self._method = "memory"
            log.warning("[IDS] No root access — using in-memory blocking only")

    def _test_nftables(self) -> bool:
        try:
            r = subprocess.run(
                ["nft", "add", "table", "inet", self.TABLE_NAME],
                capture_output=True, timeout=5
            )
            if r.returncode == 0:
                subprocess.run(
                    ["nft", "delete", "table", "inet", self.TABLE_NAME],
                    capture_output=True, timeout=5
                )
                return True
        except Exception:
            pass
        return False

    def _test_iptables(self) -> bool:
        try:
            test_ip = "192.0.2.1"
            r = subprocess.run(
                ["iptables", "-C", "INPUT", "-s", test_ip, "-j", "DROP"],
                capture_output=True, timeout=5
            )
            if r.returncode == 0:
                return True
            r = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", test_ip, "-j", "DROP"],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", test_ip, "-j", "DROP"],
                capture_output=True, timeout=5
            )
            return r.returncode == 0
        except Exception:
            pass
        return False

    def block(self, ip: str) -> bool:
        if self._method == "nftables":
            return self._nft_block(ip)
        elif self._method == "iptables":
            return self._ipt_block(ip)
        return True

    def unblock(self, ip: str) -> bool:
        if self._method == "nftables":
            return self._nft_unblock(ip)
        elif self._method == "iptables":
            return self._ipt_unblock(ip)
        return True

    def _nft_ensure_set(self):
        if self._nft_initialized:
            return
        subprocess.run(
            ["nft", "add", "table", "inet", self.TABLE_NAME],
            capture_output=True, timeout=5
        )
        subprocess.run(
            ["nft", "add", "set", "inet", self.TABLE_NAME, self.SET_NAME,
             "{ type ipv4_addr; flags timeout; timeout 24h; }"],
            capture_output=True, timeout=5
        )
        self._nft_initialized = True

    def _nft_block(self, ip: str) -> bool:
        try:
            self._nft_ensure_set()
            subprocess.run(
                ["nft", "add", "element", "inet", self.TABLE_NAME, self.SET_NAME,
                 f"{{ {ip} }}"],
                capture_output=True, timeout=5
            )
            subprocess.run(
                ["nft", "add", "rule", "inet", self.TABLE_NAME, "input",
                 f"ip saddr @pocket_wall_{self.SET_NAME} drop"],
                capture_output=True, timeout=5
            )
            return True
        except Exception:
            return False

    def _nft_unblock(self, ip: str) -> bool:
        try:
            subprocess.run(
                ["nft", "delete", "element", "inet", self.TABLE_NAME, self.SET_NAME,
                 f"{{ {ip} }}"],
                capture_output=True, timeout=5
            )
            return True
        except Exception:
            return False

    def _ipt_block(self, ip: str) -> bool:
        try:
            r = subprocess.run(
                ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5
            )
            return r.returncode == 0
        except Exception:
            return False

    def _ipt_unblock(self, ip: str) -> bool:
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=5
            )
            return True
        except Exception:
            return False

    def get_method(self) -> str:
        return self._method


class IDSEngine:
    def __init__(self, api_key: str):
        self.checker = AbuseIPDBChecker(api_key)
        self.blocker = IPBlocker()
        self._lock = Lock()

        if AI_AVAILABLE:
            try:
                self.ai = AIEngine(analysis_interval=60)
                self.ai.start_background()
            except Exception as e:
                log.error(f"[IDS] AI engine failed to initialise: {e}")
                self.ai = None
        else:
            self.ai = None

        self.events: deque[IDSEvent] = deque(maxlen=500)
        self.alerts: deque[IDSEvent] = deque(maxlen=200)
        self.stats = IDSStats()

        self._blocked_ips: set[str] = set()
        self._load_persistent_blocks()

        self.blocked_countries: set[str] = set()
        self.threshold_block = 75
        self.threshold_warn = 40
        self._load_config()

    def _load_config(self):
        try:
            with open(GEO_RULES_PATH) as f:
                cfg = json.load(f)
            self.blocked_countries = set(
                c.upper() for c in cfg.get("blocked_countries", [])
            )
            self.threshold_block = cfg.get("score_threshold_block", 75)
            self.threshold_warn = cfg.get("score_threshold_warn", 40)
        except FileNotFoundError:
            pass
        except Exception as e:
            log.error(f"[IDS] config load error: {e}")

    def save_config(self):
        try:
            cfg = {
                "blocked_countries": sorted(self.blocked_countries),
                "score_threshold_block": self.threshold_block,
                "score_threshold_warn": self.threshold_warn,
            }
            with open(GEO_RULES_PATH, "w") as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass

    def _load_persistent_blocks(self):
        if not os.path.exists(BLOCKED_IPS_FILE):
            return
        try:
            with open(BLOCKED_IPS_FILE) as f:
                data = json.load(f)
            now = time.time()
            for entry in data.get("blocks", []):
                if now - entry["timestamp"] < entry.get("ttl", CACHE_TTL):
                    self._blocked_ips.add(entry["ip"])
            log.info(f"[IDS] Loaded {len(self._blocked_ips)} persistent blocks")
        except Exception as e:
            log.error(f"[IDS] Failed to load persistent blocks: {e}")

    def _save_persistent_blocks(self):
        try:
            now = time.time()
            data = {
                "blocks": [
                    {"ip": ip, "timestamp": now, "ttl": CACHE_TTL}
                    for ip in self._blocked_ips
                ]
            }
            with open(BLOCKED_IPS_FILE, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            log.error(f"[IDS] Failed to save persistent blocks: {e}")

    def record_traffic(self, ip: str, dest_port: int = 0, dest_host: str = "",
                       request: str = "", request_len: int = 0):
        if self.ai:
            self.ai.record(ip, dest_port, dest_host, request, request_len)

    def record_error(self, ip: str):
        if self.ai:
            self.ai.record_error(ip)

    def record_anomaly(self, ip: str):
        if self.ai:
            self.ai.record_anomaly(ip)

    def add_country(self, code: str):
        with self._lock:
            self.blocked_countries.add(code.upper())
        self.save_config()

    def remove_country(self, code: str):
        with self._lock:
            self.blocked_countries.discard(code.upper())
        self.save_config()

    def check_ip(self, ip: str) -> str:
        with self._lock:
            if ip in self._blocked_ips:
                return "BLOCK"

        result = self.checker.check(ip)

        country = "???"
        isp = "Unknown"
        total_reports = 0
        is_tor = False
        rep_score = 0

        if result is None:
            action = "ALLOW"
            reason = "Private/local IP or API unavailable"
        else:
            rep_score = result["confidence_score"]
            country = result["country_code"]
            isp = result["isp"]
            total_reports = result["total_reports"]
            is_tor = result["is_tor"]

            with self._lock:
                blocked = country in self.blocked_countries

            if blocked:
                action = "BLOCK"
                reason = f"Geo-blocked: {country}"
            elif rep_score >= self.threshold_block:
                action = "BLOCK"
                reason = f"High threat score: {rep_score}%"
            elif rep_score >= self.threshold_warn:
                action = "WARN"
                reason = f"Moderate threat score: {rep_score}%"
            elif is_tor:
                action = "WARN"
                reason = "TOR exit node"
            else:
                action = "ALLOW"
                reason = "Clean"

        if action == "BLOCK":
            self._block_ip(ip)

        ev = IDSEvent(
            timestamp=time.time(),
            ip=ip,
            score=rep_score,
            country=country,
            isp=isp,
            action=action,
            reason=reason,
            total_reports=total_reports,
            is_tor=is_tor,
        )
        self._record(ev)
        return action

    def _block_ip(self, ip: str):
        with self._lock:
            if ip in self._blocked_ips:
                return
            self._blocked_ips.add(ip)
        self._save_persistent_blocks()
        success = self.blocker.block(ip)
        method = self.blocker.get_method()
        if success:
            log.info(f"[IDS] Blocked {ip} via {method}")
        else:
            log.warning(f"[IDS] System-level block failed for {ip} — in-memory only")

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

    def unblock_ip(self, ip: str):
        with self._lock:
            self._blocked_ips.discard(ip)
        self._save_persistent_blocks()
        self.blocker.unblock(ip)

    def get_blocked_ips(self) -> list[str]:
        with self._lock:
            return sorted(self._blocked_ips)

    def clear_alerts(self):
        with self._lock:
            self.alerts.clear()

    def get_ai_stats(self) -> dict:
        if self.ai:
            return self.ai.get_ai_stats()
        return {"error": "AI engine not available"}

    def get_ip_ai_details(self, ip: str) -> dict:
        if self.ai:
            return self.ai.get_ip_details(ip)
        return {"error": "AI engine not available"}

    def get_ai_alerts(self, limit=50) -> list:
        if self.ai:
            return self.ai.get_alerts(limit)
        return []


def load_api_key() -> str:
    try:
        with open(ENV_PATH) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                if key.strip() == "abuse_ipdb_api_key":
                    return val.strip()
    except FileNotFoundError:
        log.warning(f"[IDS] .env file not found at {ENV_PATH}")
    except Exception as e:
        log.error(f"[IDS] Error reading .env: {e}")
    return ""


def test_api_key(ip: str = "1.1.1.1"):
    api_key = load_api_key()
    if not api_key:
        print("[TEST] No API key found in .env")
        return

    print(f"[TEST] API key loaded ({api_key[:8]}...)")
    print(f"[TEST] Querying AbuseIPDB for {ip}...")

    checker = AbuseIPDBChecker(api_key)
    result = checker.check(ip)

    if result is None:
        print(f"[TEST] No result — IP may be private or API error")
        return

    print(f"\n[TEST] Result for {ip}:")
    print(f"  Score:       {result['confidence_score']}%")
    print(f"  Country:     {result['country_code']}")
    print(f"  ISP:         {result['isp']}")
    print(f"  Reports:     {result['total_reports']}")
    print(f"  Tor:         {result['is_tor']}")
    print(f"\n[TEST] API is working correctly!")
