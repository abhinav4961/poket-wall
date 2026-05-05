"""
Pocket-Wall Monitor — Standalone TUI that connects to the running proxy via API.
"""

import curses
import json
import time
import urllib.request
import urllib.error

API = "http://localhost:5000"

def _safe(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w - 1:
        return
    try:
        win.addnstr(y, x, str(text), w - x - 1, attr)
    except curses.error:
        pass

def _line(win, y, x, w, attr=0):
    try:
        for i in range(w):
            win.addch(y, x + i, "\u2500", attr)
    except curses.error:
        pass

def get_json(path):
    try:
        with urllib.request.urlopen(f"{API}{path}", timeout=2) as r:
            return json.loads(r.read())
    except Exception:
        return None

class Monitor:
    def __init__(self):
        self.running = True
        self.scroll = 0

    def run(self, stdscr):
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(500)

        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_GREEN)

        while self.running:
            try:
                stdscr.erase()
                h, w = stdscr.getmaxyx()
                if h < 6 or w < 30:
                    _safe(stdscr, 0, 0, "Terminal too small", curses.A_BOLD)
                    stdscr.refresh()
                    if stdscr.getch() == ord('q'):
                        self.running = False
                    continue

                self.draw(stdscr, h, w)
                stdscr.refresh()

                k = stdscr.getch()
                if k == ord('q'):
                    self.running = False
                elif k == curses.KEY_UP:
                    self.scroll = max(0, self.scroll - 1)
                elif k == curses.KEY_DOWN:
                    self.scroll += 1

            except curses.error:
                pass
            except KeyboardInterrupt:
                self.running = False

    def draw(self, scr, h, w):
        now = time.strftime("%H:%M:%S")
        _safe(scr, 0, 0, f" Pocket-Wall Monitor  |  {now}".ljust(w), curses.color_pair(6) | curses.A_BOLD)

        stats = get_json("/api/stats")
        ai_stats = get_json("/api/ai-stats")
        events = get_json("/api/events?limit=50")
        susp = []

        if ai_stats:
            # Try to get suspicious IPs (requires API support or parsing)
            # For now, we rely on ai_stats for the right panel
            pass

        # Fetch events and alerts
        alerts = []
        all_evts = events or []
        for e in all_evts:
            if e.get("action") in ("BLOCK", "WARN"):
                alerts.append(e)

        mid = w // 2
        top = 2
        ch = h - 6

        # Left: Stats & Events
        _safe(scr, top, 1, " Traffic Events ", curses.color_pair(3) | curses.A_BOLD)
        
        # Right: AI & Blocked
        _safe(scr, top, mid + 1, " AI & Security ", curses.color_pair(5) | curses.A_BOLD)
        
        for r in range(top, top + ch + 1):
            try:
                scr.addch(r, mid, "\u2502", curses.color_pair(4))
            except curses.error:
                pass

        # Stats
        if stats:
            _safe(scr, top + 1, 2, f"Total: {stats.get('total',0)}  Blocked: {stats.get('blocked',0)}", curses.color_pair(4))

        # Events List
        start = min(self.scroll, max(0, len(all_evts) - ch))
        for i, ev in enumerate(all_evts[start:start + ch]):
            row = top + 2 + i
            if row >= top + ch + 1:
                break
            ts = ev.get("time", "")
            ip = ev.get("ip", "?")
            act = ev.get("action", "?")
            sym = "\u25cf" if act == "BLOCK" else "\u25b2" if act == "WARN" else "\u2713"
            clr = curses.color_pair(1) if act == "BLOCK" else curses.color_pair(2) if act == "WARN" else curses.color_pair(3)
            
            # Truncate reason
            reason = (ev.get("reason", "")[:20] + "..") if len(ev.get("reason", "")) > 20 else ev.get("reason", "")
            
            _safe(scr, row, 2, f"{ts} {sym} {ip:<16} {act:<6} {reason}", clr)

        # Right Panel: AI Info
        r = top + 1
        if ai_stats:
            bl = ai_stats.get("baseline", {})
            _safe(scr, r, mid + 2, f"AI Model: {'Active' if ai_stats.get('model_loaded') else 'Offline'}", curses.color_pair(4) | curses.A_BOLD)
            r += 1
            _safe(scr, r, mid + 2, f"Threshold: {bl.get('threshold', 0):.3f}", curses.color_pair(5))
            r += 1
            _safe(scr, r, mid + 2, f"Total Alerts: {ai_stats.get('total_alerts', 0)}", curses.color_pair(1))
        else:
            _safe(scr, r, mid + 2, "API Connection Error", curses.color_pair(1))
            r += 2

        # Blocked IPs List
        r += 1
        _safe(scr, r, mid + 2, "Recent Blocks:", curses.color_pair(1) | curses.A_BOLD)
        r += 1
        
        blocks = [e for e in alerts if e.get("action") == "BLOCK"]
        for e in blocks[:4]:
            if r >= top + ch + 1:
                break
            _safe(scr, r, mid + 2, f"  {e.get('ip', '?')}  S:{e.get('score', 0)}", curses.color_pair(1))
            r += 1

        if not blocks:
            _safe(scr, r, mid + 2, "  (none)", curses.color_pair(3))

        # Footer
        fy = top + ch + 1
        _line(scr, fy, 0, w, curses.color_pair(4))
        _safe(scr, fy + 1, 2, "[q]Quit  [Up/Dn]Scroll", curses.color_pair(7) | curses.A_BOLD)

if __name__ == "__main__":
    curses.wrapper(Monitor().run)
