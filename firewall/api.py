"""
Pocket-Wall — REST API for the dashboard.
Built with Python stdlib only (http.server) — zero dependencies.
Runs alongside the proxy on port 5000.
"""

import json
import os
import time
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler

from firewall import BLACKLIST, is_blocked, build_blacklist, log
from firewall import _request_times, _banned_ips, _lock as flood_lock, FLOOD_THRESHOLD, FLOOD_BAN_DURATION

ids_engine = None

RULES_FILE = os.path.join(os.path.dirname(__file__), "rules.json")
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "piwall.log")
MAX_LOG_LINES = 500


def _event_to_dict(ev):
    return {
        "timestamp": ev.timestamp,
        "time": time.strftime("%H:%M:%S", time.localtime(ev.timestamp)),
        "ip": ev.ip,
        "score": ev.score,
        "ai_score": round(ev.ai_score, 3) if hasattr(ev, "ai_score") else 0.0,
        "country": ev.country,
        "isp": ev.isp,
        "action": ev.action,
        "reason": ev.reason,
        "total_reports": ev.total_reports,
        "is_tor": ev.is_tor,
    }


class APIHandler(BaseHTTPRequestHandler):

    def log_message(self, fmt, *args):
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

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = dict(urllib.parse.parse_qsl(parsed.query))

        routes = {
            "/api/stats": self._handle_stats,
            "/api/events": lambda: self._handle_events(query),
            "/api/alerts": self._handle_alerts,
            "/api/rules": self._handle_get_rules,
            "/api/geo": self._handle_get_geo,
            "/api/blocked-ips": self._handle_blocked_ips,
            "/api/logs": lambda: self._handle_logs(query),
            "/api/flood-status": self._handle_flood_status,
            "/api/ai-stats": self._handle_ai_stats,
            "/api/ai-ip": lambda: self._handle_ai_ip(query),
        }

        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._send_json({"error": "Not found"}, 404)

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        body = self._read_body()

        routes = {
            "/api/rules": lambda: self._handle_post_rules(body),
            "/api/geo/country": lambda: self._handle_post_country(body),
            "/api/geo/thresholds": lambda: self._handle_post_thresholds(body),
            "/api/unblock": lambda: self._handle_unblock(body),
            "/api/check-domain": lambda: self._handle_check_domain(body),
        }

        handler = routes.get(path)
        if handler:
            handler()
        else:
            self._send_json({"error": "Not found"}, 404)

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
        new_bl = build_blacklist()
        try:
            with open(RULES_FILE, "w") as f:
                json.dump({"blacklist": blacklist}, f, indent=2)
        except Exception as e:
            return self._send_json({"error": str(e)}, 500)

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
        lines = min(int(query.get("lines", 50)), MAX_LOG_LINES)
        try:
            with open(LOG_FILE) as f:
                all_lines = f.readlines()
            self._send_json({"lines": all_lines[-lines:]})
        except Exception:
            self._send_json({"lines": []})

    def _handle_flood_status(self):
        now = time.time()
        with flood_lock:
            banned = {ip: exp for ip, exp in _banned_ips.items() if exp > now}
        self._send_json({
            "threshold": FLOOD_THRESHOLD,
            "ban_duration": FLOOD_BAN_DURATION,
            "banned_ips": [{"ip": ip, "expires_in": int(exp - now)} for ip, exp in banned.items()],
        })

    def _handle_ai_stats(self):
        if ids_engine is None:
            return self._send_json({"error": "IDS not running"}, 503)
        self._send_json(ids_engine.get_ai_stats())

    def _handle_ai_ip(self, query):
        if ids_engine is None:
            return self._send_json({"error": "IDS not running"}, 503)
        ip = query.get("ip", "")
        if not ip:
            return self._send_json({"error": "No IP provided"}, 400)
        self._send_json(ids_engine.get_ip_ai_details(ip))


def start_api_server(engine=None, host="0.0.0.0", port=5000):
    global ids_engine
    ids_engine = engine

    server = HTTPServer((host, port), APIHandler)
    log.info(f"[API] REST server running on http://{host}:{port}")
    server.serve_forever()
