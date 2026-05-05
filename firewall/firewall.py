import json
import logging
import os
import time
import urllib.request
from collections import defaultdict
from threading import Lock

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RULES_PATH = os.path.join(BASE_DIR, "rules.json")
if not os.path.exists(RULES_PATH):
    RULES_PATH = os.path.join(os.path.dirname(BASE_DIR), "rules.json")

os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler("logs/piwall.log"),
    ]
)

log = logging.getLogger("piwall")
_log_to_console = False


def enable_console_logging():
    global _log_to_console
    if not _log_to_console:
        log.addHandler(logging.StreamHandler())
        _log_to_console = True


def disable_console_logging():
    global _log_to_console
    if _log_to_console:
        for handler in log.handlers[:]:
            if isinstance(handler, logging.StreamHandler):
                log.removeHandler(handler)
        _log_to_console = False

BLOCKLIST_SOURCES = {
    "stevenblack": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "urlhaus": "https://urlhaus.abuse.ch/downloads/hostfile/",
}

CACHE_DIR = "blocklist_cache"
CACHE_TTL = 86400


def _fetch_and_cache(name, url):
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_file = os.path.join(CACHE_DIR, f"{name}.txt")

    if os.path.exists(cache_file):
        age = time.time() - os.path.getmtime(cache_file)
        if age < CACHE_TTL:
            log.info(f"[blocklist] using cached {name}")
            with open(cache_file) as f:
                return f.read()

    try:
        log.info(f"[blocklist] downloading {name}")
        with urllib.request.urlopen(url, timeout=10) as r:
            content = r.read().decode(errors="ignore")

        with open(cache_file, "w") as f:
            f.write(content)

        return content
    except Exception as e:
        log.warning(f"[blocklist] failed {name}: {e}")
        if os.path.exists(cache_file):
            log.info(f"[blocklist] using stale cache for {name}")
            with open(cache_file) as f:
                return f.read()
        return ""


def _parse_hosts(content):
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            domains.add(parts[1].lower())

    return domains


def build_blacklist():
    domains = set()

    for name, url in BLOCKLIST_SOURCES.items():
        content = _fetch_and_cache(name, url)
        parsed = _parse_hosts(content)
        log.info(f"[blocklist] {name}: {len(parsed)} domains")
        domains.update(parsed)

    try:
        with open(RULES_PATH) as f:
            data = json.load(f)
            local = set(d.lower() for d in data.get("blacklist", []))
            domains.update(local)
            log.info(f"[rules] loaded {len(local)} local rules")
    except Exception as e:
        log.warning(f"[rules] load failed: {e}")

    log.info(f"[blacklist] total {len(domains)} domains")
    return domains


BLACKLIST = build_blacklist()

_request_times = defaultdict(list)
_banned_ips = {}
_lock = Lock()

FLOOD_THRESHOLD = 20
FLOOD_BAN_DURATION = 60
FLOOD_CLEANUP_INTERVAL = 300
_last_flood_cleanup = 0


def _cleanup_flood_data():
    global _last_flood_cleanup
    now = time.time()
    if now - _last_flood_cleanup < FLOOD_CLEANUP_INTERVAL:
        return
    _last_flood_cleanup = now
    cutoff = now - 2
    with _lock:
        expired = [ip for ip, exp in _banned_ips.items() if exp < now]
        for ip in expired:
            del _banned_ips[ip]
        stale = [ip for ip, times in _request_times.items() if not times or all(t < cutoff for t in times)]
        for ip in stale:
            del _request_times[ip]


def check_flood(ip):
    _cleanup_flood_data()
    now = time.time()

    with _lock:
        if ip in _banned_ips:
            if now < _banned_ips[ip]:
                return True
            else:
                del _banned_ips[ip]

        times = _request_times[ip]
        times[:] = [t for t in times if now - t < 1]
        times.append(now)

        if len(times) > FLOOD_THRESHOLD:
            _banned_ips[ip] = now + FLOOD_BAN_DURATION
            log.warning(f"[flood] {ip} banned")
            return True

    return False


def is_blocked(host):
    host = host.lower()
    parts = host.split(".")

    for i in range(len(parts)):
        if ".".join(parts[i:]) in BLACKLIST:
            return True

    return False