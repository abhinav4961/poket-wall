"""
TUI Dashboard for Pocket-Wall IDS — built with curses (stdlib).
Integrates Firewall + AI dashboards with seamless switching.
"""

import curses
import time
from threading import Lock
from ai_tui import AITUI

SYM_SHIELD = "\u26e8"
SYM_BLOCK  = "\u25cf"
SYM_WARN   = "\u25b2"
SYM_OK     = "\u2713"
SYM_ARROW  = "\u25b6"
SYM_ALERT  = "\u26a0"
SYM_AI     = "\u25c6"
SYM_LINE   = "\u2500"
SYM_VLINE  = "\u2502"
SYM_UL     = "\u250c"
SYM_UR     = "\u2510"
SYM_LL     = "\u2514"
SYM_LR     = "\u2518"
SYM_HORIZ  = "\u2501"


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


def _draw_box(win, y, x, h, w, title="", color=4):
    if h < 2 or w < 2:
        return
    try:
        win.addch(y, x, SYM_UL, curses.color_pair(color))
        win.addch(y, x + w - 1, SYM_UR, curses.color_pair(color))
        win.addch(y + h - 1, x, SYM_LL, curses.color_pair(color))
        win.addch(y + h - 1, x + w - 1, SYM_LR, curses.color_pair(color))
        for i in range(1, w - 1):
            win.addch(y, x + i, SYM_HORIZ, curses.color_pair(color))
            win.addch(y + h - 1, x + i, SYM_HORIZ, curses.color_pair(color))
        for i in range(1, h - 1):
            win.addch(y + i, x, SYM_VLINE, curses.color_pair(color))
            win.addch(y + i, x + w - 1, SYM_VLINE, curses.color_pair(color))
        if title:
            _safe_addstr(win, y, x + 2, f" {title} ", curses.color_pair(color) | curses.A_BOLD)
    except curses.error:
        pass


class TUI:
    """Curses-based IDS dashboard with integrated AI view."""

    def __init__(self, ids_engine):
        self.ids = ids_engine
        self._running = True
        self._view = "firewall"
        self._mode = "main"
        self._geo_input = ""
        self._thresh_input = ""
        self._thresh_field = 0
        self._scroll_traffic = 0
        self._lock = Lock()
        self._ai_tui = AITUI(ids_engine) if ids_engine.ai else None
        self._ai_tui._embedded = True

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
        curses.init_pair(9, curses.COLOR_WHITE, curses.COLOR_MAGENTA)
        curses.init_pair(10, curses.COLOR_RED, -1)

        while self._running:
            try:
                stdscr.erase()
                h, w = stdscr.getmaxyx()

                if h < 20 or w < 60:
                    _safe_addstr(stdscr, 0, 0, "Terminal too small. Need 60x20+", curses.A_BOLD | curses.color_pair(1))
                    stdscr.refresh()
                    key = stdscr.getch()
                    if key == ord('q'):
                        self._running = False
                    continue

                if self._view == "firewall":
                    self._draw_firewall(stdscr, h, w)
                elif self._view == "ai":
                    self._ai_tui.draw(stdscr, h, w)

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

        if self._view == "ai":
            if key == ord('q'):
                self._running = False
            elif key == 27 or key == ord('f'):
                self._view = "firewall"
                self._ai_tui._mode = "overview"
            else:
                self._ai_tui.handle_key(key)
            return

        # Firewall view
        if key == ord('q'):
            self._running = False
        elif key == ord('a') and self._ai_tui:
            self._view = "ai"
            return

        if self._mode == "geo":
            if key == 27:
                self._mode = "main"
            elif key in (curses.KEY_ENTER, 10, 13):
                self._process_geo_input()
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                self._geo_input = self._geo_input[:-1]
            elif 32 <= key <= 126:
                self._geo_input += chr(key)
        elif self._mode == "thresholds":
            if key == 27:
                self._mode = "main"
            elif key == ord('\t'):
                self._thresh_field = 1 - self._thresh_field
                self._thresh_input = ""
            elif key in (curses.KEY_ENTER, 10, 13):
                self._process_thresh_input()
            elif key in (curses.KEY_BACKSPACE, 127, 8):
                self._thresh_input = self._thresh_input[:-1]
            elif 48 <= key <= 57:
                self._thresh_input += chr(key)
        elif self._mode == "blocked":
            if key == 27 or key == ord('b'):
                self._mode = "main"
            elif key == ord('u'):
                ips = self.ids.get_blocked_ips()
                if ips:
                    self.ids.unblock_ip(ips[-1])
        else:
            # Main mode
            if key == ord('g'):
                self._mode = "geo"
                self._geo_input = ""
            elif key == ord('t'):
                self._mode = "thresholds"
                self._thresh_input = ""
                self._thresh_field = 0
            elif key == ord('c'):
                self.ids.clear_alerts()
            elif key == ord('b'):
                self._mode = "blocked"
            elif key == curses.KEY_UP:
                self._scroll_traffic = max(0, self._scroll_traffic - 1)
            elif key == curses.KEY_DOWN:
                self._scroll_traffic += 1

    def _process_geo_input(self):
        raw = self._geo_input.strip().upper()
        if not raw:
            return
        if raw.startswith("-"):
            code = raw[1:].strip()
            if len(code) == 2:
                self.ids.remove_country(code)
        else:
            code = raw.lstrip("+").strip()
            if len(code) == 2:
                self.ids.add_country(code)
        self._geo_input = ""

    def _process_thresh_input(self):
        try:
            val = int(self._thresh_input)
            val = max(0, min(100, val))
            if self._thresh_field == 0:
                self.ids.threshold_block = val
            else:
                self.ids.threshold_warn = val
            self.ids.save_config()
        except ValueError:
            pass
        self._thresh_input = ""

    def _draw_firewall(self, stdscr, h, w):
        now = time.strftime("%H:%M:%S")
        title = f" {SYM_SHIELD}  POCKET-WALL FIREWALL  |  {now}  "
        _safe_addstr(stdscr, 0, 0, title.center(w), curses.color_pair(7) | curses.A_BOLD)
        _safe_addstr(stdscr, 1, 0, SYM_LINE * w, curses.color_pair(4))

        stats = self.ids.stats

        if self._mode == "main":
            bar_w = w - 4
            bar_y = 3
            _safe_addstr(stdscr, bar_y, 2, f" Total: {stats.total}  Blocked: {stats.blocked}  Warned: {stats.warned}  Allowed: {stats.allowed} ", curses.color_pair(4) | curses.A_BOLD)

            if stats.total > 0:
                bar_y += 1
                blocked_w = int((stats.blocked / stats.total) * bar_w)
                warned_w = int((stats.warned / stats.total) * bar_w)
                allowed_w = bar_w - blocked_w - warned_w
                _safe_addstr(stdscr, bar_y, 2, SYM_BLOCK * max(blocked_w, 0), curses.color_pair(1))
                _safe_addstr(stdscr, bar_y, 2 + blocked_w, SYM_WARN * max(warned_w, 0), curses.color_pair(2))
                _safe_addstr(stdscr, bar_y, 2 + blocked_w + warned_w, SYM_OK * max(allowed_w, 0), curses.color_pair(3))

            split = w // 2
            panel_top = 6
            panel_h = h - 11

            _draw_box(stdscr, panel_top, 1, panel_h, split - 1, f" {SYM_ARROW} LIVE TRAFFIC ", 4)
            _draw_box(stdscr, panel_top, split, panel_h, w - split - 1, f" {SYM_ALERT} ALERTS ", 1)

            self._draw_traffic(stdscr, panel_top + 1, 2, split - 3, panel_h - 2)
            self._draw_alerts(stdscr, panel_top + 1, split + 1, w - split - 3, panel_h - 2)

            bottom_y = panel_top + panel_h
            _safe_addstr(stdscr, bottom_y, 0, SYM_LINE * w, curses.color_pair(4))

            geo_str = ", ".join(sorted(self.ids.blocked_countries)) if self.ids.blocked_countries else "None"
            _safe_addstr(stdscr, bottom_y + 1, 2,
                         f"GEO-BLOCKED: {geo_str}  |  Block: >= {self.ids.threshold_block}%  Warn: >= {self.ids.threshold_warn}%  |  Method: {self.ids.blocker.get_method()}",
                         curses.color_pair(5))

            keys = "[q]Quit [a]AI [g]Geo [t]Threshold [c]Clear [b]Blocked [Up/Down]Scroll"
            _safe_addstr(stdscr, h - 2, 2, keys, curses.color_pair(8) | curses.A_BOLD)

            block_pct = stats.blocked / max(stats.total, 1) * 100
            _safe_addstr(stdscr, h - 1, 2,
                         f"Block Rate: {block_pct:.1f}%  |  Alerts: {len(self.ids.alerts)}  |  Blocked IPs: {len(self.ids.get_blocked_ips())}",
                         curses.color_pair(10))

        elif self._mode == "geo":
            self._draw_geo(stdscr, h, w)
        elif self._mode == "thresholds":
            self._draw_thresholds(stdscr, h, w)
        elif self._mode == "blocked":
            self._draw_blocked(stdscr, h, w)

    def _draw_traffic(self, win, start_y, start_x, width, height):
        events = list(self.ids.events)
        if not events:
            _safe_addstr(win, start_y, start_x, "Waiting for traffic...", curses.color_pair(4))
            return

        total = len(events)
        max_scroll = max(0, total - height)
        if self._scroll_traffic > max_scroll:
            self._scroll_traffic = max_scroll

        visible = events[max(0, total - height - self._scroll_traffic):total - self._scroll_traffic] if self._scroll_traffic > 0 else events[max(0, total - height):]

        for i, ev in enumerate(visible):
            if i >= height:
                break
            y = start_y + i
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

            line = f"{ts} {ev.ip:<16} {ev.country:>3} {sym} {ev.score:>3}%  {ev.reason[:max(width - 40, 1)]}"
            _safe_addstr(win, y, start_x, line[:width], color)

    def _draw_alerts(self, win, start_y, start_x, width, height):
        alerts = list(self.ids.alerts)
        if not alerts:
            _safe_addstr(win, start_y, start_x, "No alerts yet.", curses.color_pair(3))
            return

        alerts = list(reversed(alerts))
        row = 0
        for ev in alerts:
            if row >= height:
                break
            ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))

            if ev.action == "BLOCK":
                sym = SYM_BLOCK
                color = curses.color_pair(1) | curses.A_BOLD
            else:
                sym = SYM_WARN
                color = curses.color_pair(2)

            line = f"{sym} {ts} {ev.ip:<16} S:{ev.score}% {ev.country}"
            _safe_addstr(win, start_y + row, start_x, line[:width], color)
            row += 1

            if row < height:
                reason = f"  {ev.reason[:width-3]}"
                _safe_addstr(win, start_y + row, start_x, reason[:width], curses.color_pair(4))
                row += 1

    def _draw_geo(self, stdscr, h, w):
        _safe_addstr(stdscr, 0, 0, " GEO-BLOCK EDITOR ", curses.color_pair(7) | curses.A_BOLD)
        _safe_addstr(stdscr, 1, 0, SYM_LINE * w, curses.color_pair(4))

        _safe_addstr(stdscr, 3, 2, "Currently blocked countries:", curses.color_pair(4) | curses.A_BOLD)

        if self.ids.blocked_countries:
            countries = sorted(self.ids.blocked_countries)
            for i in range(0, len(countries), 10):
                row_str = "  ".join(countries[i:i+10])
                _safe_addstr(stdscr, 5 + i // 10, 4, row_str, curses.color_pair(1) | curses.A_BOLD)
        else:
            _safe_addstr(stdscr, 5, 4, "(none — add countries below)", curses.color_pair(3))

        _safe_addstr(stdscr, h - 6, 2, "Type a 2-letter country code to ADD (e.g. CN)", curses.color_pair(4))
        _safe_addstr(stdscr, h - 5, 2, "Prefix with - to REMOVE (e.g. -CN)", curses.color_pair(4))
        _safe_addstr(stdscr, h - 4, 2, "Press ENTER to apply, ESC to go back", curses.color_pair(4))

        _safe_addstr(stdscr, h - 2, 2, f"Input: {self._geo_input}_", curses.color_pair(5) | curses.A_BOLD)

    def _draw_thresholds(self, stdscr, h, w):
        _safe_addstr(stdscr, 0, 0, " THRESHOLD SETTINGS ", curses.color_pair(7) | curses.A_BOLD)
        _safe_addstr(stdscr, 1, 0, SYM_LINE * w, curses.color_pair(4))

        block_color = curses.color_pair(1) | curses.A_BOLD if self._thresh_field == 0 else curses.color_pair(4)
        warn_color = curses.color_pair(2) | curses.A_BOLD if self._thresh_field == 1 else curses.color_pair(4)

        _safe_addstr(stdscr, 3, 2, f"{'>' if self._thresh_field == 0 else ' '} Block threshold: {self.ids.threshold_block}%",
                     block_color)
        _safe_addstr(stdscr, 4, 2, "  (IPs with score >= this are BLOCKED)", curses.color_pair(4))

        _safe_addstr(stdscr, 6, 2, f"{'>' if self._thresh_field == 1 else ' '} Warn threshold:  {self.ids.threshold_warn}%",
                     warn_color)
        _safe_addstr(stdscr, 7, 2, "  (IPs with score >= this get a WARNING)", curses.color_pair(4))

        _safe_addstr(stdscr, 9, 2, "TAB to switch fields, type a number, ENTER to set", curses.color_pair(4))
        _safe_addstr(stdscr, 10, 2, "ESC to go back", curses.color_pair(4))

        _safe_addstr(stdscr, h - 2, 2, f"New value: {self._thresh_input}_", curses.color_pair(5) | curses.A_BOLD)

    def _draw_blocked(self, stdscr, h, w):
        _safe_addstr(stdscr, 0, 0, " BLOCKED IPs ", curses.color_pair(7) | curses.A_BOLD)
        _safe_addstr(stdscr, 1, 0, SYM_LINE * w, curses.color_pair(4))

        ips = self.ids.get_blocked_ips()
        if not ips:
            _safe_addstr(stdscr, 3, 2, "No IPs currently blocked.", curses.color_pair(3))
        else:
            for i, ip in enumerate(ips):
                if i + 3 >= h - 3:
                    _safe_addstr(stdscr, i + 3, 2, f"... and {len(ips) - i} more", curses.color_pair(4))
                    break
                _safe_addstr(stdscr, i + 3, 2, f"{SYM_BLOCK} {ip}", curses.color_pair(1))

        _safe_addstr(stdscr, h - 3, 2, "[u] Unblock last IP", curses.color_pair(4))
        _safe_addstr(stdscr, h - 2, 2, "[ESC/b] Back to main", curses.color_pair(4))
