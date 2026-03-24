import json
import logging
import os
import time
import urllib.request
from collections import defaultdict
from threading import Lock

# ------------------ LOGGING ------------------
os.makedirs("logs", exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler("logs/piwall.log"),
        logging.StreamHandler()
    ]
)

log = logging.getLogger("piwall")

# ------------------ BLOCKLIST ------------------
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
            return open(cache_file).read()

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
            return open(cache_file).read()
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
        with open("rules.json") as f:
            data = json.load(f)
            local = set(d.lower() for d in data.get("blacklist", []))
            domains.update(local)
            log.info(f"[rules] loaded {len(local)} local rules")
    except Exception as e:
        log.warning(f"[rules] load failed: {e}")

    log.info(f"[blacklist] total {len(domains)} domains")
    return domains


BLACKLIST = build_blacklist()

# ------------------ FLOOD PROTECTION ------------------
_request_times = defaultdict(list)
_banned_ips = {}
_lock = Lock()

FLOOD_THRESHOLD = 20
FLOOD_BAN_DURATION = 60


def check_flood(ip):
    now = time.time()

    with _lock:
        if ip in _banned_ips:
            if now < _banned_ips[ip]:
                return True
            else:
                del _banned_ips[ip]

        times = _request_times[ip]
        times = [t for t in times if now - t < 1]
        times.append(now)
        _request_times[ip] = times

        if len(times) > FLOOD_THRESHOLD:
            _banned_ips[ip] = now + FLOOD_BAN_DURATION
            log.warning(f"[flood] {ip} banned")
            return True

    return False


# ------------------ DOMAIN CHECK ------------------
def is_blocked(host):
    host = host.split(":")[0].lower()
    parts = host.split(".")

    for i in range(len(parts)):
        if ".".join(parts[i:]) in BLACKLIST:
            return True

    return False