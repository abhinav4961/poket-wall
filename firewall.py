import json
import logging
import os
import time
import urllib.request
from collections import defaultdict
from threading import Lock

# Logging setup
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

# blocklists (cached locally)
BLOCKLIST_SOURCES = {
    "stevenblack": "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts",
    "urlhaus":     "https://urlhaus.abuse.ch/downloads/hostfile/",
}
CACHE_DIR  = "blocklist_cache"
CACHE_TTL  = 86400  # 24 hours in seconds

def _fetch_and_cache(name, url):
    os.makedirs(CACHE_DIR, exist_ok=True)
    cache_file = os.path.join(CACHE_DIR, f"{name}.txt")

    # Use cache if fresh
    if os.path.exists(cache_file):
        age = time.time() - os.path.getmtime(cache_file)
        if age < CACHE_TTL:
            log.info(f"[blocklist] using cached {name}")
            with open(cache_file) as f:
                return f.read()

    # Download fresh copy
    try:
        log.info(f"[blocklist] downloading {name} ...")
        with urllib.request.urlopen(url, timeout=10) as r:
            content = r.read().decode(errors="ignore")
        with open(cache_file, "w") as f:
            f.write(content)
        log.info(f"[blocklist] {name} updated")
        return content
    except Exception as e:
        log.warning(f"[blocklist] failed to fetch {name}: {e}")
        # Fall back to stale cache if available
        if os.path.exists(cache_file):
            with open(cache_file) as f:
                return f.read()
        return ""

def _parse_hosts_file(content):
    """Parse a hosts-format file and return a set of domains."""
    domains = set()
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        
        # hosts format: 0.0.0.0 domain.com
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            domain = parts[1].lower()
            if domain not in ("localhost", "0.0.0.0", "broadcasthost"):
                domains.add(domain)
    return domains

def load_universal_blocklist():
    domains = set()
    for name, url in BLOCKLIST_SOURCES.items():
        content = _fetch_and_cache(name, url)
        parsed  = _parse_hosts_file(content)
        log.info(f"[blocklist] {name}: {len(parsed):,} domains loaded")
        domains.update(parsed)
    return domains

# Local rules 
def load_local_rules():
    try:
        with open("rules.json") as f:
            data = json.load(f)
        rules = set(d.strip().lower() for d in data.get("blacklist", []))
        log.info(f"[rules] local rules loaded: {len(rules)} domains")
        return rules
    except Exception as e:
        log.warning(f"[rules] could not load rules.json: {e}")
        return set()

# Build master blacklist 
def build_blacklist():
    local     = load_local_rules()
    universal = load_universal_blocklist()
    combined  = local | universal
    log.info(f"[blacklist] total: {len(combined):,} domains")
    return combined

BLACKLIST = build_blacklist()

# Flood detection
FLOOD_THRESHOLD = 20        # max requests per second per IP
FLOOD_BAN_DURATION = 60     # seconds to ban a flooding IP

_request_times  = defaultdict(list)   # ip -> [timestamps]
_banned_ips     = {}                   # ip -> unban_timestamp
_flood_lock     = Lock()

def check_flood(ip):
    """
    Returns True if the IP should be blocked due to flooding.
    Tracks request timestamps per IP and bans if threshold exceeded.
    """
    now = time.time()

    with _flood_lock:
        # Check if currently banned
        if ip in _banned_ips:
            if now < _banned_ips[ip]:
                return True
            else:
                del _banned_ips[ip]
                log.info(f"[flood] {ip} unbanned")

        # Slide the window — keep only last 1 second
        times = _request_times[ip]
        _request_times[ip] = [t for t in times if now - t < 1.0]
        _request_times[ip].append(now)

        if len(_request_times[ip]) > FLOOD_THRESHOLD:
            _banned_ips[ip] = now + FLOOD_BAN_DURATION
            log.warning(f"[flood] {ip} BANNED for {FLOOD_BAN_DURATION}s (exceeded {FLOOD_THRESHOLD} req/s)")
            return True

    return False

# Domain check 
def is_blocked(host):
    host  = host.split(":")[0].lower()
    parts = host.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in BLACKLIST:
            return True
    return False