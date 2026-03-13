import json

# Load blacklist from rules.json
def load_rules():
    with open("rules.json") as f:
        data = json.load(f)
    return set(d.strip().lower() for d in data.get("blacklist", []))

BLACKLIST = load_rules()

def is_blocked(host):
    # Strip port if present (e.g. youtube.com:443 -> youtube.com)
    host = host.split(":")[0].lower()
    # Check host and all parent domains
    parts = host.split(".")
    for i in range(len(parts)):
        if ".".join(parts[i:]) in BLACKLIST:
            return True
    return False
