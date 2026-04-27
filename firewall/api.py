"""
Pocket-Wall — REST API for the React dashboard.
Built with Python stdlib only (http.server) — zero dependencies.
Runs alongside the proxy on port 5000.
"""

import json
import os
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread

from firewall import BLACKLIST, is_blocked, build_blacklist, log
from firewall import _request_times, _banned_ips, FLOOD_THRESHOLD, FLOOD_BAN_DURATION

# These get set by main.py before the server starts
ids_engine = None

RULES_FILE = os.path.join(os.path.dirname(__file__), "..", "rules.json")
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "piwall.log")


def _event_to_dict(ev):
    return {
        "timestamp": ev.timestamp,
        "time": time.strftime("%H:%M:%S", time.localtime(ev.timestamp)),
        "ip": ev.ip,
        "score": ev.score,
        "country": ev.country,
        "isp": ev.isp,
        "action": ev.action,
        "reason": ev.reason,
        "total_reports": ev.total_reports,
        "is_tor": ev.is_tor,
    }


class APIHandler(BaseHTTPRequestHandler):
    """Handle REST API requests with CORS support."""

    def log_message(self, fmt, *args):
        """Suppress default stderr logging."""
        pass

    def _send_json(self, data, status=200):
        body = json.dumps(data).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        raw = self.rfile.read(length)
        try:
            return json.loads(raw.decode())
        except Exception:
            return {}

    def _parse_query(self):
        parsed = urllib.parse.urlparse(self.path)
        return dict(urllib.parse.parse_qsl(parsed.query))

    def _route_path(self):
        return urllib.parse.urlparse(self.path).path

    # ─── CORS preflight ───
    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    # ─── GET routes ───
    def do_GET(self):
        path = self._route_path()
        query = self._parse_query()

        if path == "/api/stats":
            self._handle_stats()
        elif path == "/api/events":
            self._handle_events(query)
        elif path == "/api/alerts":
            self._handle_alerts()
        elif path == "/api/rules":
            self._handle_get_rules()
        elif path == "/api/geo":
            self._handle_get_geo()
        elif path == "/api/blocked-ips":
            self._handle_blocked_ips()
        elif path == "/api/logs":
            self._handle_logs(query)
        elif path == "/api/flood-status":
            self._handle_flood_status()
        else:
            self._send_json({"error": "Not found"}, 404)

    # ─── POST routes ───
    def do_POST(self):
        path = self._route_path()
        body = self._read_body()

        if path == "/api/rules":
            self._handle_post_rules(body)
        elif path == "/api/geo/country":
            self._handle_post_country(body)
        elif path == "/api/geo/thresholds":
            self._handle_post_thresholds(body)
        elif path == "/api/unblock":
            self._handle_unblock(body)
        elif path == "/api/check-domain":
            self._handle_check_domain(body)
        else:
            self._send_json({"error": "Not found"}, 404)

    # ─────────────────── HANDLERS ───────────────────

    def _handle_stats(self):
        if ids_engine is None:
            return self._send_json({"total": 0, "blocked": 0, "warned": 0, "allowed": 0})
        s = ids_engine.stats
        self._send_json({
            "total": s.total,
            "blocked": s.blocked,
            "warned": s.warned,
            "allowed": s.allowed,
        })

    def _handle_events(self, query):
        if ids_engine is None:
            return self._send_json([])
        limit = int(query.get("limit", 100))
        events = list(ids_engine.events)[-limit:]
        self._send_json([_event_to_dict(e) for e in events])

    def _handle_alerts(self):
        if ids_engine is None:
            return self._send_json([])
        alerts = list(ids_engine.alerts)
        alerts.reverse()
        self._send_json([_event_to_dict(a) for a in alerts])

    def _handle_get_rules(self):
        try:
            with open(RULES_FILE) as f:
                data = json.load(f)
            self._send_json(data)
        except Exception:
            self._send_json({"blacklist": []})

    def _handle_post_rules(self, body):
        blacklist = body.get("blacklist", [])
        try:
            with open(RULES_FILE, "w") as f:
                json.dump({"blacklist": blacklist}, f, indent=2)
        except Exception as e:
            return self._send_json({"error": str(e)}, 500)

        new_bl = build_blacklist()
        BLACKLIST.clear()
        BLACKLIST.update(new_bl)
        self._send_json({"ok": True, "count": len(blacklist)})

    def _handle_get_geo(self):
        if ids_engine is None:
            return self._send_json({
                "blocked_countries": [],
                "threshold_block": 75,
                "threshold_warn": 40,
            })
        self._send_json({
            "blocked_countries": sorted(ids_engine.blocked_countries),
            "threshold_block": ids_engine.threshold_block,
            "threshold_warn": ids_engine.threshold_warn,
        })

    def _handle_post_country(self, body):
        if ids_engine is None:
            return self._send_json({"error": "IDS not running"}, 503)
        code = body.get("code", "").upper()
        action = body.get("action", "add")
        if len(code) != 2:
            return self._send_json({"error": "Invalid country code"}, 400)
        if action == "add":
            ids_engine.add_country(code)
        else:
            ids_engine.remove_country(code)
        self._send_json({"ok": True, "blocked_countries": sorted(ids_engine.blocked_countries)})

    def _handle_post_thresholds(self, body):
        if ids_engine is None:
            return self._send_json({"error": "IDS not running"}, 503)
        block = body.get("threshold_block")
        warn = body.get("threshold_warn")
        if block is not None:
            ids_engine.threshold_block = max(0, min(100, int(block)))
        if warn is not None:
            ids_engine.threshold_warn = max(0, min(100, int(warn)))
        ids_engine.save_config()
        self._send_json({
            "ok": True,
            "threshold_block": ids_engine.threshold_block,
            "threshold_warn": ids_engine.threshold_warn,
        })

    def _handle_blocked_ips(self):
        if ids_engine is None:
            return self._send_json([])
        self._send_json(ids_engine.get_blocked_ips())

    def _handle_unblock(self, body):
        if ids_engine is None:
            return self._send_json({"error": "IDS not running"}, 503)
        ip = body.get("ip", "")
        ids_engine.unblock_ip(ip)
        self._send_json({"ok": True, "blocked": ids_engine.get_blocked_ips()})

    def _handle_check_domain(self, body):
        domain = body.get("domain", "").strip().lower()
        if not domain:
            return self._send_json({"error": "No domain provided"}, 400)
        blocked = is_blocked(domain)
        self._send_json({"domain": domain, "blocked": blocked})

    def _handle_logs(self, query):
        lines = int(query.get("lines", 50))
        try:
            with open(LOG_FILE) as f:
                all_lines = f.readlines()
            self._send_json({"lines": all_lines[-lines:]})
        except Exception:
            self._send_json({"lines": []})

    def _handle_flood_status(self):
        now = time.time()
        banned = {ip: exp for ip, exp in _banned_ips.items() if exp > now}
        self._send_json({
            "threshold": FLOOD_THRESHOLD,
            "ban_duration": FLOOD_BAN_DURATION,
            "banned_ips": [{"ip": ip, "expires_in": int(exp - now)} for ip, exp in banned.items()],
        })


# ─────────────────── SERVER ───────────────────

def start_api_server(engine=None, host="0.0.0.0", port=5000):
    """Start the API HTTP server (blocking)."""
    global ids_engine
    ids_engine = engine

    server = HTTPServer((host, port), APIHandler)
    log.info(f"[API] REST server running on http://{host}:{port}")
    server.serve_forever()
