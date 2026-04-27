"""
TUI Dashboard for Pocket-Wall IDS — built with curses (stdlib).
"""

import curses
import os
import time
from threading import Lock


# Unicode symbols with ASCII fallbacks
SYM_SHIELD = "\u26e8"     # ⛨
SYM_BLOCK  = "\u25cf"     # ●
SYM_WARN   = "\u25b2"     # ▲
SYM_OK     = "\u2713"     # ✓
SYM_ARROW  = "\u25b6"     # ▶


def _safe_addstr(win, y, x, text, attr=0):
    """Write string to window, truncating to fit and ignoring curses errors."""
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


class TUI:
    """Curses-based IDS dashboard."""

    def __init__(self, ids_engine):
        self.ids = ids_engine
        self._running = True
        self._mode = "main"     # "main", "geo", "thresholds", "blocked"
        self._geo_input = ""
        self._thresh_input = ""
        self._thresh_field = 0  # 0 = block, 1 = warn
        self._scroll_traffic = 0
        self._scroll_alerts = 0
        self._lock = Lock()

    def run(self, stdscr):
        """Entry point — called via curses.wrapper(tui.run)."""
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(500)  # refresh every 500ms

        # Init colors
        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)       # block/danger
        curses.init_pair(2, curses.COLOR_YELLOW, -1)    # warn
        curses.init_pair(3, curses.COLOR_GREEN, -1)     # ok
        curses.init_pair(4, curses.COLOR_CYAN, -1)      # header/info
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)   # accent
        curses.init_pair(6, curses.COLOR_WHITE, curses.COLOR_RED)    # alert bg
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_CYAN)   # header bg
        curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_GREEN)  # status bar

        while self._running:
            try:
                stdscr.erase()
                h, w = stdscr.getmaxyx()

                if h < 15 or w < 50:
                    _safe_addstr(stdscr, 0, 0, "Terminal too small. Need 50x15+", curses.A_BOLD)
                    stdscr.refresh()
                    key = stdscr.getch()
                    if key == ord('q'):
                        self._running = False
                    continue

                if self._mode == "main":
                    self._draw_main(stdscr, h, w)
                elif self._mode == "geo":
                    self._draw_geo(stdscr, h, w)
                elif self._mode == "thresholds":
                    self._draw_thresholds(stdscr, h, w)
                elif self._mode == "blocked":
                    self._draw_blocked(stdscr, h, w)

                stdscr.refresh()

                key = stdscr.getch()
                self._handle_key(key)

            except curses.error:
                pass
            except KeyboardInterrupt:
                self._running = False

    # ==================== KEY HANDLING ====================

    def _handle_key(self, key):
        if key == -1:
            return

        if self._mode == "main":
            if key == ord('q'):
                self._running = False
            elif key == ord('g'):
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

        elif self._mode == "geo":
            if key == 27:  # ESC
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
            elif 48 <= key <= 57:  # digits only
                self._thresh_input += chr(key)

        elif self._mode == "blocked":
            if key == 27 or key == ord('b'):
                self._mode = "main"
            elif key == ord('u'):
                # unblock last IP
                ips = self.ids.get_blocked_ips()
                if ips:
                    self.ids.unblock_ip(ips[-1])

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

    # ==================== MAIN SCREEN ====================

    def _draw_main(self, stdscr, h, w):
        # Header bar
        header = f" {SYM_SHIELD}  POCKET-WALL IDS "
        stats = self.ids.stats
        stat_str = f"Total:{stats.total} Blocked:{stats.blocked} Warned:{stats.warned} Clean:{stats.allowed}"
        header_line = header + " " * max(0, w - len(header) - len(stat_str) - 1) + stat_str
        _safe_addstr(stdscr, 0, 0, header_line[:w], curses.color_pair(7) | curses.A_BOLD)

        # Divider
        _safe_addstr(stdscr, 1, 0, "\u2500" * w, curses.color_pair(4))

        # Calculate panel sizes
        split = w // 2
        panel_h = h - 5  # leave room for header(2) + status bar(3)

        # Left panel header — LIVE TRAFFIC
        _safe_addstr(stdscr, 2, 1, f"{SYM_ARROW} LIVE TRAFFIC", curses.color_pair(4) | curses.A_BOLD)

        # Right panel header — ALERTS
        _safe_addstr(stdscr, 2, split + 1, f"!! ALERTS", curses.color_pair(1) | curses.A_BOLD)

        # Vertical divider
        for y in range(2, 2 + panel_h):
            _safe_addstr(stdscr, y, split, "\u2502", curses.color_pair(4))

        # Draw traffic
        self._draw_traffic(stdscr, 3, 1, split - 2, panel_h - 1)

        # Draw alerts
        self._draw_alerts(stdscr, 3, split + 1, w - split - 2, panel_h - 1)

        # Bottom separator
        bottom_y = 2 + panel_h
        _safe_addstr(stdscr, bottom_y, 0, "\u2500" * w, curses.color_pair(4))

        # Geo-block status
        geo_str = ", ".join(sorted(self.ids.blocked_countries)) if self.ids.blocked_countries else "None"
        _safe_addstr(stdscr, bottom_y + 1, 1,
                     f"GEO-BLOCKED: {geo_str}  |  Thresholds: Block>={self.ids.threshold_block} Warn>={self.ids.threshold_warn}",
                     curses.color_pair(5))

        # Keybindings
        keys = "[q]Quit [g]Geo-block [t]Thresholds [c]Clear alerts [b]Blocked IPs [Up/Down]Scroll"
        _safe_addstr(stdscr, bottom_y + 2, 1, keys, curses.color_pair(8) | curses.A_BOLD)

    def _draw_traffic(self, win, start_y, start_x, width, height):
        events = list(self.ids.events)
        if not events:
            _safe_addstr(win, start_y, start_x, "Waiting for traffic...", curses.color_pair(4))
            return

        # Scroll to bottom by default, or use manual scroll
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

            line = f"{ts} {ev.ip:<16} {ev.country:>3} {sym} {ev.score:>3}%"
            _safe_addstr(win, y, start_x, line[:width], color)

    def _draw_alerts(self, win, start_y, start_x, width, height):
        alerts = list(self.ids.alerts)
        if not alerts:
            _safe_addstr(win, start_y, start_x, "No alerts yet.", curses.color_pair(3))
            return

        # Show most recent first
        alerts = list(reversed(alerts))

        for i, ev in enumerate(alerts[:height]):
            y = start_y + i
            ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))

            if ev.action == "BLOCK":
                sym = SYM_BLOCK
                color = curses.color_pair(1) | curses.A_BOLD
            else:
                sym = SYM_WARN
                color = curses.color_pair(2)

            line1 = f"{sym} {ev.ip:<16} Score:{ev.score} {ev.country}"
            _safe_addstr(win, y, start_x, line1[:width], color)

            if i + 1 < height:
                reason_line = f"  {ev.reason}"
                _safe_addstr(win, y + 1, start_x, reason_line[:width],
                           curses.color_pair(4))
                # skip an extra line for the reason
                # Actually we need to handle this better — use 2 lines per alert
                pass

        # Re-draw with 2-line alerts
        win_ref = win
        for i in range(0, len(alerts)):
            row = i * 2
            if row >= height:
                break
            ev = alerts[i]
            y = start_y + row
            ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))

            if ev.action == "BLOCK":
                sym = SYM_BLOCK
                color = curses.color_pair(1) | curses.A_BOLD
            else:
                sym = SYM_WARN
                color = curses.color_pair(2)

            line1 = f"{sym} {ts} {ev.ip}"
            _safe_addstr(win_ref, y, start_x, line1[:width], color)

            if row + 1 < height:
                line2 = f"  {ev.action} S:{ev.score} {ev.country} {ev.reason[:width-15]}"
                _safe_addstr(win_ref, y + 1, start_x, line2[:width], curses.color_pair(4))

    # ==================== GEO-BLOCK EDITOR ====================

    def _draw_geo(self, stdscr, h, w):
        _safe_addstr(stdscr, 0, 0, " GEO-BLOCK EDITOR ", curses.color_pair(7) | curses.A_BOLD)
        _safe_addstr(stdscr, 1, 0, "\u2500" * w, curses.color_pair(4))

        _safe_addstr(stdscr, 3, 2, "Currently blocked countries:", curses.color_pair(4) | curses.A_BOLD)

        if self.ids.blocked_countries:
            countries = sorted(self.ids.blocked_countries)
            # Display in rows of 10
            for i in range(0, len(countries), 10):
                row_str = "  ".join(countries[i:i+10])
                _safe_addstr(stdscr, 5 + i // 10, 4, row_str, curses.color_pair(1) | curses.A_BOLD)
        else:
            _safe_addstr(stdscr, 5, 4, "(none)", curses.color_pair(3))

        _safe_addstr(stdscr, h - 6, 2, "Type a 2-letter country code to ADD (e.g. CN)", curses.color_pair(4))
        _safe_addstr(stdscr, h - 5, 2, "Prefix with - to REMOVE (e.g. -CN)", curses.color_pair(4))
        _safe_addstr(stdscr, h - 4, 2, "Press ENTER to apply, ESC to go back", curses.color_pair(4))

        _safe_addstr(stdscr, h - 2, 2, f"Input: {self._geo_input}_", curses.color_pair(5) | curses.A_BOLD)

    # ==================== THRESHOLD EDITOR ====================

    def _draw_thresholds(self, stdscr, h, w):
        _safe_addstr(stdscr, 0, 0, " THRESHOLD SETTINGS ", curses.color_pair(7) | curses.A_BOLD)
        _safe_addstr(stdscr, 1, 0, "\u2500" * w, curses.color_pair(4))

        block_color = curses.color_pair(1) | curses.A_BOLD if self._thresh_field == 0 else curses.color_pair(4)
        warn_color = curses.color_pair(2) | curses.A_BOLD if self._thresh_field == 1 else curses.color_pair(4)

        _safe_addstr(stdscr, 3, 2, f"{'>' if self._thresh_field == 0 else ' '} Block threshold: {self.ids.threshold_block}%",
                     block_color)
        _safe_addstr(stdscr, 4, 2, f"  (IPs with score >= this are BLOCKED via iptables)", curses.color_pair(4))

        _safe_addstr(stdscr, 6, 2, f"{'>' if self._thresh_field == 1 else ' '} Warn threshold:  {self.ids.threshold_warn}%",
                     warn_color)
        _safe_addstr(stdscr, 7, 2, f"  (IPs with score >= this get a WARNING alert)", curses.color_pair(4))

        _safe_addstr(stdscr, 9, 2, "TAB to switch fields, type a number, ENTER to set", curses.color_pair(4))
        _safe_addstr(stdscr, 10, 2, "ESC to go back", curses.color_pair(4))

        _safe_addstr(stdscr, h - 2, 2, f"New value: {self._thresh_input}_", curses.color_pair(5) | curses.A_BOLD)

    # ==================== BLOCKED IPS LIST ====================

    def _draw_blocked(self, stdscr, h, w):
        _safe_addstr(stdscr, 0, 0, " BLOCKED IPs (iptables) ", curses.color_pair(7) | curses.A_BOLD)
        _safe_addstr(stdscr, 1, 0, "\u2500" * w, curses.color_pair(4))

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

    def stop(self):
        self._running = False
