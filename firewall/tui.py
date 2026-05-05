"""
TUI Dashboard for Pocket-Wall — simple 3-column layout.
Left: All connections | Middle: Blocked | Right: AI Analysis
"""

import curses
import time

SYM_SHIELD = "\u26e8"
SYM_BLOCK  = "\u25cf"
SYM_WARN   = "\u25b2"
SYM_OK     = "\u2713"
SYM_LINE   = "\u2500"
SYM_VLINE  = "\u2502"
SYM_UL     = "\u250c"
SYM_UR     = "\u2510"
SYM_LL     = "\u2514"
SYM_LR     = "\u2518"


def _safe_addstr(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w:
        return
    max_len = w - x - 1
    if max_len <= 0:
        return
    try:
        win.addnstr(y, x, text, max_len, attr)
    except curses.error:
        pass


def _draw_hline(win, y, x, w, color=4):
    try:
        for i in range(w):
            win.addch(y, x + i, SYM_LINE, curses.color_pair(color))
    except curses.error:
        pass


class TUI:

    def __init__(self, ids_engine):
        self.ids = ids_engine
        self._running = True
        self._scroll_conn = 0
        self._scroll_blocked = 0
        self._scroll_ai = 0

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
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_RED)
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_GREEN)

        while self._running:
            try:
                stdscr.erase()
                h, w = stdscr.getmaxyx()

                if h < 10 or w < 40:
                    _safe_addstr(stdscr, 0, 0, "Terminal too small (need 40x10)", curses.A_BOLD | curses.color_pair(1))
                    stdscr.refresh()
                    key = stdscr.getch()
                    if key == ord('q'):
                        self._running = False
                    continue

                self._draw(stdscr, h, w)
                stdscr.refresh()

                key = stdscr.getch()
                self._handle_key(key)

            except curses.error:
                pass
            except KeyboardInterrupt:
                self._running = False

    def _handle_key(self, key):
        if key == -1:
            return
        if key == ord('q'):
            self._running = False
        elif key == curses.KEY_UP:
            self._scroll_conn = max(0, self._scroll_conn - 1)
        elif key == curses.KEY_DOWN:
            self._scroll_conn += 1
        elif key == ord('p'):
            self._scroll_blocked = max(0, self._scroll_blocked - 1)
        elif key == ord(';'):
            self._scroll_blocked += 1
        elif key == ord('c'):
            self.ids.clear_alerts()

    def _draw(self, stdscr, h, w):
        now = time.strftime("%H:%M:%S")
        title = f" {SYM_SHIELD}  POCKET-WALL  |  {now}  ".center(w)
        _safe_addstr(stdscr, 0, 0, title, curses.color_pair(7) | curses.A_BOLD)

        stats = self.ids.stats
        stat_line = f"Total: {stats.total}  Allowed: {stats.allowed}  Blocked: {stats.blocked}  Warned: {stats.warned}"
        _safe_addstr(stdscr, 1, 2, stat_line, curses.color_pair(4) | curses.A_BOLD)
        _draw_hline(stdscr, 2, 0, w)

        split1 = w // 3
        split2 = (w * 2) // 3
        top = 3
        content_h = h - 7

        # Column headers
        _safe_addstr(stdscr, top, 1, " ALL CONNECTIONS ", curses.color_pair(3) | curses.A_BOLD)
        _draw_hline(stdscr, top, split1, 1)
        _safe_addstr(stdscr, top, split1 + 2, " BLOCKED & ALERTS ", curses.color_pair(1) | curses.A_BOLD)
        _draw_hline(stdscr, top, split2, 1)
        _safe_addstr(stdscr, top, split2 + 2, " AI ANALYSIS ", curses.color_pair(5) | curses.A_BOLD)

        # Vertical dividers
        for i in range(top + 1, top + content_h + 1):
            try:
                stdscr.addch(i, split1, SYM_VLINE, curses.color_pair(4))
                stdscr.addch(i, split2, SYM_VLINE, curses.color_pair(4))
            except curses.error:
                pass

        # Column 1: All Connections
        self._draw_connections(stdscr, top + 1, 1, split1 - 2, content_h)

        # Column 2: Blocked & Alerts
        self._draw_blocked(stdscr, top + 1, split1 + 2, split2 - split1 - 3, content_h)

        # Column 3: AI Analysis
        self._draw_ai(stdscr, top + 1, split2 + 2, w - split2 - 3, content_h)

        # Footer
        footer_y = top + content_h + 1
        _draw_hline(stdscr, footer_y, 0, w)
        _safe_addstr(stdscr, footer_y + 1, 2, "[q]Quit [c]Clear alerts [Up/Dn]Scroll connections [p/;]Scroll blocked",
                     curses.color_pair(8) | curses.A_BOLD)

        geo = ", ".join(sorted(self.ids.blocked_countries)) if self.ids.blocked_countries else "None"
        _safe_addstr(stdscr, h - 1, 2, f"Geo: {geo}  |  Blocker: {self.ids.blocker.get_method()}  |  Block threshold: {self.ids.threshold_block}%", curses.color_pair(5))

    def _draw_connections(self, win, y, x, w, h):
        events = list(self.ids.events)
        if not events:
            _safe_addstr(win, y, x, "Waiting...", curses.color_pair(4))
            return

        total = len(events)
        start = min(self._scroll_conn, max(0, total - h))
        visible = events[start:start + h]

        for i, ev in enumerate(visible):
            if i >= h:
                break
            ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))

            if ev.action == "BLOCK":
                sym = SYM_BLOCK
                color = curses.color_pair(1) | curses.A_BOLD
            elif ev.action == "WARN":
                sym = SYM_WARN
                color = curses.color_pair(2)
            else:
                sym = SYM_OK
                color = curses.color_pair(3)

            line = f"{ts} {sym} {ev.ip:<16} {ev.country:>3} {ev.score:>3}% {ev.reason[:w-36]}"
            _safe_addstr(win, y + i, x, line[:w], color)

    def _draw_blocked(self, win, y, x, w, h):
        blocked = [e for e in self.ids.events if e.action == "BLOCK"]
        warned = [e for e in self.ids.events if e.action == "WARN"]
        items = blocked + warned

        if not items:
            _safe_addstr(win, y, x, "All clear", curses.color_pair(3))
            return

        items = list(reversed(items))
        start = min(self._scroll_blocked, max(0, len(items) - h))
        visible = items[start:start + h]

        for i, ev in enumerate(visible):
            if i >= h:
                break
            ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
            sym = SYM_BLOCK if ev.action == "BLOCK" else SYM_WARN
            color = curses.color_pair(1) if ev.action == "BLOCK" else curses.color_pair(2)

            line = f"{ts} {sym} {ev.ip:<16} S:{ev.score} {ev.reason[:w-30]}"
            _safe_addstr(win, y + i, x, line[:w], color | curses.A_BOLD)

    def _draw_ai(self, win, y, x, w, h):
        ai = self.ids.ai if hasattr(self.ids, 'ai') else None
        row = y

        if not ai:
            _safe_addstr(win, row, x, "AI disabled", curses.color_pair(1) | curses.A_BOLD)
            return

        stats = ai.get_ai_stats()
        baseline = stats.get("baseline", {})
        suspicious = ai.get_suspicious_ips()
        alerts = ai.get_alerts(10)

        _safe_addstr(win, row, x, f"Model: {'ON' if stats.get('model_loaded') else 'OFF'}", curses.color_pair(4) | curses.A_BOLD)
        row += 1
        _safe_addstr(win, row, x, f"Alerts: {stats.get('total_alerts', 0)}", curses.color_pair(2))
        row += 1
        _safe_addstr(win, row, x, f"Threshold: {baseline.get('threshold', 0):.3f}", curses.color_pair(5))
        row += 1

        if suspicious:
            _safe_addstr(win, row, x, f"Suspicious: {len(suspicious)}", curses.color_pair(1) | curses.A_BOLD)
            row += 1
            top_susp = sorted(suspicious.items(), key=lambda s: s[1], reverse=True)[:5]
            for ip, score in top_susp:
                if row >= y + h:
                    break
                risk = "CRIT" if score >= 0.85 else "HIGH" if score >= 0.7 else "MED" if score >= 0.5 else "LOW"
                color = curses.color_pair(1) if score >= 0.7 else curses.color_pair(2)
                bar = "\u2588" * int(score * 10) + "\u2591" * (10 - int(score * 10))
                _safe_addstr(win, row, x, f"  {ip:<16} {bar} {score:.2f} {risk}", color)
                row += 1
        else:
            _safe_addstr(win, row, x, "Suspicious: None", curses.color_pair(3))
            row += 1

        if alerts and row < y + h - 2:
            row += 1
            _safe_addstr(win, row, x, "Recent AI:", curses.color_pair(5) | curses.A_BOLD)
            row += 1
            for a in reversed(alerts[-3:]):
                if row >= y + h:
                    break
                ts = time.strftime("%H:%M", time.localtime(a.get("timestamp", 0)))
                v = a.get("verdict", "?")[0]
                _safe_addstr(win, row, x, f"  {ts} {v} {a.get('ip', '?'):16} {a.get('score', 0):.2f}", curses.color_pair(4))
                row += 1
