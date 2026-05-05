"""
AI Dashboard TUI for Pocket-Wall — dedicated AI analysis monitor.
Shows alerts, suspicious IPs, behavioral analysis, and actionable suggestions.
Can be used standalone via run() or embedded in main TUI via draw()/handle_key().
"""

import curses
import math
import time

SYM_SHIELD = "\u26e8"
SYM_BLOCK  = "\u25cf"
SYM_WARN   = "\u25b2"
SYM_OK     = "\u2713"
SYM_ALERT  = "\u26a0"
SYM_AI     = "\u25c6"
SYM_LIGHT  = "\u25cf"
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


def _risk_label(score):
    if score >= 0.85:
        return "CRITICAL", 1
    elif score >= 0.7:
        return "HIGH", 1
    elif score >= 0.5:
        return "MEDIUM", 2
    elif score >= 0.3:
        return "LOW", 3
    return "SAFE", 3


def _score_bar(score, width):
    filled = int(score * width)
    filled = min(filled, width)
    if score >= 0.7:
        return SYM_BLOCK * filled + "\u2591" * (width - filled), curses.color_pair(1)
    elif score >= 0.5:
        return SYM_WARN * filled + "\u2591" * (width - filled), curses.color_pair(2)
    return "\u2588" * filled + "\u2591" * (width - filled), curses.color_pair(3)


def _detect_attack_type(features):
    if not features:
        return "Unknown"
    conn_rate = features.get("conn_rate", 0)
    unique_ports = features.get("unique_ports", 0)
    error_rate = features.get("error_rate", 0)
    special_chars = features.get("special_char_ratio", 0)
    burst_count = features.get("burst_count", 0)
    anomalies = features.get("protocol_anomalies", 0)

    if unique_ports > 10 and error_rate > 0.5:
        return "Port Scan"
    if special_chars > 0.1 and features.get("avg_request_len", 0) > 400:
        return "Injection Attack (SQLi/XSS)"
    if burst_count > 15 and error_rate > 0.3:
        return "Brute Force"
    if conn_rate > 1.0 and burst_count > 20:
        return "DDoS / Flood"
    if anomalies > 0 or special_chars > 0.05:
        return "Protocol Abuse"
    return "Anomalous Behavior"


class AITUI:
    """AI Dashboard — alerts, suspicious IPs, suggestions.
    
    Can be used standalone (run()) or embedded in main TUI (draw() + handle_key()).
    """

    def __init__(self, ids_engine):
        self.ids = ids_engine
        self.ai = ids_engine.ai if ids_engine else None
        self._running = True
        self._mode = "overview"
        self._scroll_alerts = 0
        self._scroll_suspicious = 0
        self._selected_ip = None
        self._detail_scroll = 0
        self._embedded = False

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
        curses.init_pair(10, curses.COLOR_RED, curses.COLOR_BLACK)
        curses.init_pair(11, curses.COLOR_YELLOW, curses.COLOR_BLACK)
        curses.init_pair(12, curses.COLOR_GREEN, curses.COLOR_BLACK)

        self._embedded = False
        while self._running:
            try:
                stdscr.erase()
                h, w = stdscr.getmaxyx()

                if h < 20 or w < 70:
                    _safe_addstr(stdscr, 0, 0, "Terminal too small. Need 70x20+", curses.A_BOLD | curses.color_pair(1))
                    stdscr.refresh()
                    key = stdscr.getch()
                    if key == ord('q'):
                        self._running = False
                    continue

                self.draw(stdscr, h, w)
                stdscr.refresh()

                key = stdscr.getch()
                self.handle_key(key)

            except curses.error:
                pass
            except KeyboardInterrupt:
                self._running = False

    def handle_key(self, key):
        if key == -1:
            return

        if self._embedded and (key == 27 or key == ord('f')):
            self._mode = "overview"
            return

        if self._mode == "overview":
            if key == ord('q'):
                self._running = False
            elif key == ord('s'):
                self._mode = "suspicious"
                self._scroll_suspicious = 0
            elif key == ord('j'):
                self._mode = "suggestions"
            elif key == curses.KEY_UP:
                self._scroll_alerts = max(0, self._scroll_alerts - 1)
            elif key == curses.KEY_DOWN:
                self._scroll_alerts += 1

        elif self._mode == "suspicious":
            if key == 27 or key == ord('s'):
                self._mode = "overview"
            elif key == curses.KEY_UP:
                self._scroll_suspicious = max(0, self._scroll_suspicious - 1)
            elif key == curses.KEY_DOWN:
                self._scroll_suspicious += 1
            elif key in (curses.KEY_ENTER, 10, 13):
                susp = self.ai.get_suspicious_ips() if self.ai else {}
                if susp:
                    sorted_ips = sorted(susp.items(), key=lambda x: x[1], reverse=True)
                    idx = min(self._scroll_suspicious, len(sorted_ips) - 1)
                    self._selected_ip = sorted_ips[idx][0]
                    self._mode = "ip_detail"
                    self._detail_scroll = 0

        elif self._mode == "suggestions":
            if key == 27 or key == ord('j'):
                self._mode = "overview"

        elif self._mode == "ip_detail":
            if key == 27 or key == ord('s'):
                self._mode = "suspicious"
                self._selected_ip = None
            elif key == curses.KEY_UP:
                self._detail_scroll = max(0, self._detail_scroll - 1)
            elif key == curses.KEY_DOWN:
                self._detail_scroll += 1
            elif key == ord('u'):
                if self._selected_ip:
                    self.ids.unblock_ip(self._selected_ip)

    def draw(self, stdscr, h, w):
        if self._mode == "overview":
            self._draw_overview(stdscr, h, w)
        elif self._mode == "suspicious":
            self._draw_suspicious(stdscr, h, w)
        elif self._mode == "suggestions":
            self._draw_suggestions(stdscr, h, w)
        elif self._mode == "ip_detail":
            self._draw_ip_detail(stdscr, h, w)

    def _draw_overview(self, stdscr, h, w):
        now = time.strftime("%H:%M:%S")
        title = f" {SYM_AI}  POCKET-WALL AI DASHBOARD  |  {now}  "
        _safe_addstr(stdscr, 0, 0, title.center(w), curses.color_pair(9) | curses.A_BOLD)
        _safe_addstr(stdscr, 1, 0, SYM_LINE * w, curses.color_pair(5))

        if not self.ai:
            _safe_addstr(stdscr, 3, 2, "AI engine not available.", curses.color_pair(1) | curses.A_BOLD)
            _safe_addstr(stdscr, 4, 2, "[ESC/f] Back to Firewall", curses.color_pair(4))
            return

        stats = self.ai.get_ai_stats()
        baseline = stats.get("baseline", {})

        row = 3
        _safe_addstr(stdscr, row, 2, f"Model: {'Loaded' if stats.get('model_loaded') else 'Not loaded'} | Trees: {stats.get('tree_count', 0)} | Interval: {stats.get('interval_sec', 0)}s | Analyses: {stats.get('analyses_run', 0)}", curses.color_pair(4) | curses.A_BOLD)
        row += 1

        bar_w = w - 6
        threshold = baseline.get("threshold", 0.5)
        mean = baseline.get("mean", 0)
        std = baseline.get("std", 0)
        _safe_addstr(stdscr, row, 2, f"Baseline: mean={mean:.3f}  std={std:.3f}  threshold={threshold:.3f}  samples={baseline.get('samples', 0)}", curses.color_pair(5))
        row += 1

        _safe_addstr(stdscr, row, 2, f"Total Alerts: {stats.get('total_alerts', 0)}", curses.color_pair(1) | curses.A_BOLD)
        row += 2

        split = w // 2
        left_h = h - row - 4
        if left_h < 4:
            return

        _draw_box(stdscr, row, 1, left_h, split - 1, f" {SYM_ALERT} RECENT AI ALERTS ", 1)
        _draw_box(stdscr, row, split, left_h, w - split - 1, f" {SYM_LIGHT} THREAT LEVEL ", 5)

        self._draw_ai_alerts(stdscr, row + 1, 2, split - 3, left_h - 2)
        self._draw_threat_meter(stdscr, row + 1, split + 1, w - split - 3, left_h - 2)

        bottom_y = h - 3
        _safe_addstr(stdscr, bottom_y, 0, SYM_LINE * w, curses.color_pair(4))
        keys = "[ESC/f]Firewall [s]Suspicious IPs [j]Suggestions [Up/Down]Scroll"
        _safe_addstr(stdscr, h - 1, 2, keys, curses.color_pair(8) | curses.A_BOLD)

    def _draw_ai_alerts(self, win, start_y, start_x, width, height):
        if not self.ai:
            return
        alerts = self.ai.get_alerts(100)
        if not alerts:
            _safe_addstr(win, start_y, start_x, "No AI alerts yet.", curses.color_pair(3))
            return

        alerts = list(reversed(alerts))
        max_scroll = max(0, len(alerts) - height)
        if self._scroll_alerts > max_scroll:
            self._scroll_alerts = max_scroll

        visible = alerts[self._scroll_alerts:self._scroll_alerts + height]
        for i, alert in enumerate(visible):
            y = start_y + i
            ts = time.strftime("%H:%M:%S", time.localtime(alert.get("timestamp", 0)))
            score = alert.get("score", 0)
            risk, color = _risk_label(score)
            ip = alert.get("ip", "?")

            line = f"{ts} {ip:<16} [{risk:>8}] {score:.2f}"
            _safe_addstr(win, y, start_x, line[:width], curses.color_pair(color) | curses.A_BOLD)

    def _draw_threat_meter(self, win, start_y, start_x, width, height):
        if not self.ai:
            return

        suspicious = self.ai.get_suspicious_ips()
        critical = sum(1 for s in suspicious.values() if s >= 0.85)
        high = sum(1 for s in suspicious.values() if 0.7 <= s < 0.85)
        medium = sum(1 for s in suspicious.values() if 0.5 <= s < 0.7)
        low = sum(1 for s in suspicious.values() if 0.3 <= s < 0.5)

        row = start_y
        _safe_addstr(win, row, start_x, f"  Suspicious IPs: {len(suspicious)}", curses.color_pair(4) | curses.A_BOLD)
        row += 2

        categories = [
            ("CRITICAL", critical, 1),
            ("HIGH", high, 1),
            ("MEDIUM", medium, 2),
            ("LOW", low, 3),
        ]
        bar_w = width - 14
        for label, count, color in categories:
            if row >= start_y + height - 1:
                break
            bar, bar_color = _score_bar(min(count / max(len(suspicious), 1), 1.0), bar_w)
            _safe_addstr(win, row, start_x + 2, f"{label:>8}: {count:3d} ", curses.color_pair(color))
            _safe_addstr(win, row, start_x + 14, bar[:bar_w], bar_color)
            row += 1

        row += 1
        if row < start_y + height - 2:
            if critical > 0:
                _safe_addstr(win, row, start_x + 2, "ACTION: Immediate investigation required!", curses.color_pair(1) | curses.A_BOLD | curses.A_BLINK)
                row += 1
            if high > 0:
                _safe_addstr(win, row, start_x + 2, "WARN: High-risk IPs detected, consider blocking", curses.color_pair(1))
                row += 1
            if medium > 0:
                _safe_addstr(win, row, start_x + 2, "MONITOR: Suspicious patterns detected", curses.color_pair(2))
                row += 1
            if len(suspicious) == 0:
                _safe_addstr(win, row, start_x + 2, "All clear — no suspicious activity", curses.color_pair(3))

    def _draw_suspicious(self, stdscr, h, w):
        now = time.strftime("%H:%M:%S")
        title = f" {SYM_LIGHT}  SUSPICIOUS IP ANALYSIS  |  {now}  "
        _safe_addstr(stdscr, 0, 0, title.center(w), curses.color_pair(9) | curses.A_BOLD)
        _safe_addstr(stdscr, 1, 0, SYM_LINE * w, curses.color_pair(5))

        if not self.ai:
            _safe_addstr(stdscr, 3, 2, "AI engine not available.", curses.color_pair(1))
            return

        suspicious = self.ai.get_suspicious_ips()
        if not suspicious:
            _safe_addstr(stdscr, 3, 2, "No suspicious IPs detected. Network traffic appears normal.", curses.color_pair(3) | curses.A_BOLD)
            _safe_addstr(stdscr, h - 1, 2, "[ESC/f] Back", curses.color_pair(8) | curses.A_BOLD)
            return

        sorted_ips = sorted(suspicious.items(), key=lambda x: x[1], reverse=True)

        _safe_addstr(stdscr, 3, 2, f"Total suspicious IPs: {len(suspicious)}", curses.color_pair(4) | curses.A_BOLD)

        content_h = h - 6
        max_scroll = max(0, len(sorted_ips) - content_h)
        if self._scroll_suspicious > max_scroll:
            self._scroll_suspicious = max_scroll

        visible = sorted_ips[self._scroll_suspicious:self._scroll_suspicious + content_h]
        for i, (ip, score) in enumerate(visible):
            y = 5 + i
            risk, color = _risk_label(score)
            features = self.ai.extractor.get_features(ip)
            attack_type = _detect_attack_type(features)

            bar_str, bar_color = _score_bar(score, 20)
            _safe_addstr(stdscr, y, 2, f"{i + self._scroll_suspicious + 1:>3}. {ip:<16}", curses.color_pair(4))
            _safe_addstr(stdscr, y, 23, f"[{risk:>8}]", curses.color_pair(color) | curses.A_BOLD)
            _safe_addstr(stdscr, y, 35, bar_str, bar_color)
            _safe_addstr(stdscr, y, 57, f"{score:.3f}", curses.color_pair(color))
            _safe_addstr(stdscr, y, 64, f"~ {attack_type}", curses.color_pair(2))

            if y + 1 < h - 2:
                feature_summary = f"     conn_rate={features.get('conn_rate', 0):.2f} ports={features.get('unique_ports', 0)} errors={features.get('error_rate', 0):.2f} burst={features.get('burst_count', 0)}"
                _safe_addstr(stdscr, y + 1, 2, feature_summary[:w-3], curses.color_pair(4))

        _safe_addstr(stdscr, h - 2, 2, "Press ENTER for details | [u] unblock selected | [ESC/f] Back", curses.color_pair(8) | curses.A_BOLD)

    def _draw_suggestions(self, stdscr, h, w):
        now = time.strftime("%H:%M:%S")
        title = f" {SYM_AI}  AI SECURITY SUGGESTIONS  |  {now}  "
        _safe_addstr(stdscr, 0, 0, title.center(w), curses.color_pair(9) | curses.A_BOLD)
        _safe_addstr(stdscr, 1, 0, SYM_LINE * w, curses.color_pair(5))

        if not self.ai:
            _safe_addstr(stdscr, 3, 2, "AI engine not available.", curses.color_pair(1))
            return

        alerts = self.ai.get_alerts(100)
        suspicious = self.ai.get_suspicious_ips()

        row = 3
        suggestions = []

        if not alerts and not suspicious:
            _safe_addstr(stdscr, row, 2, "No suggestions — your network looks healthy!", curses.color_pair(3) | curses.A_BOLD)
        else:
            _safe_addstr(stdscr, row, 2, "Recommendations based on current traffic analysis:", curses.color_pair(4) | curses.A_BOLD)
            row += 2

            critical_ips = [(ip, s) for ip, s in suspicious.items() if s >= 0.85]
            if critical_ips:
                suggestions.append((1, "CRITICAL", f"Immediately block {len(critical_ips)} critical-risk IP(s): {', '.join(ip for ip, _ in critical_ips[:3])}", curses.color_pair(1) | curses.A_BOLD))

            high_ips = [(ip, s) for ip, s in suspicious.items() if 0.7 <= s < 0.85]
            if high_ips:
                suggestions.append((2, "HIGH", f"Consider blocking {len(high_ips)} high-risk IP(s) showing attack patterns", curses.color_pair(1)))

            medium_ips = [(ip, s) for ip, s in suspicious.items() if 0.5 <= s < 0.7]
            if medium_ips:
                suggestions.append((3, "MEDIUM", f"Monitor {len(medium_ips)} medium-risk IP(s) — add to watchlist", curses.color_pair(2)))

            stats = self.ai.get_ai_stats()
            baseline = stats.get("baseline", {})
            if baseline.get("threshold", 1.0) < 0.4:
                suggestions.append((4, "TUNING", "AI threshold is low — consider raising it to reduce false positives", curses.color_pair(2)))
            elif baseline.get("threshold", 0) > 0.8:
                suggestions.append((4, "TUNING", "AI threshold is high — you may miss subtle attacks", curses.color_pair(2)))

            if stats.get("total_alerts", 0) > 50:
                suggestions.append((5, "POLICY", f"High alert count ({stats['total_alerts']}) — review and tighten blocklist rules", curses.color_pair(2)))

            if self.ids.blocker.get_method() == "memory":
                suggestions.append((6, "SYSTEM", "Running without root — enable iptables/nftables for real IP blocking", curses.color_pair(2)))

            if not self.ids.blocked_countries:
                suggestions.append((7, "GEO", "No geo-blocking configured — consider blocking known hostile regions", curses.color_pair(2)))

            suggestions.append((8, "BEST PRACTICE", "Regularly update blocklists and review blocked IPs", curses.color_pair(3)))
            suggestions.append((9, "BEST PRACTICE", "Monitor AI baseline drift over time for accuracy", curses.color_pair(3)))

            for priority, level, text, color in suggestions:
                if row >= h - 3:
                    break
                _safe_addstr(stdscr, row, 2, f"[P{priority}] {level}: {text[:w-16]}", color)
                row += 1

        _safe_addstr(stdscr, h - 2, 2, "[ESC/f] Back", curses.color_pair(8) | curses.A_BOLD)

    def _draw_ip_detail(self, stdscr, h, w):
        if not self._selected_ip or not self.ai:
            self._mode = "suspicious"
            return

        ip = self._selected_ip
        score = self.ai.get_ip_score(ip)
        risk, color = _risk_label(score)
        features = self.ai.extractor.get_features(ip)
        attack_type = _detect_attack_type(features)

        title = f" {SYM_LIGHT}  IP DETAIL: {ip}  |  Risk: {risk}  |  Score: {score:.3f}  "
        _safe_addstr(stdscr, 0, 0, title.center(w), curses.color_pair(color) | curses.A_BOLD)
        _safe_addstr(stdscr, 1, 0, SYM_LINE * w, curses.color_pair(5))

        row = 3
        bar_str, bar_color = _score_bar(score, 40)
        _safe_addstr(stdscr, row, 2, f"Anomaly Score: {score:.4f}", curses.color_pair(4) | curses.A_BOLD)
        _safe_addstr(stdscr, row, 24, bar_str, bar_color)
        row += 1
        _safe_addstr(stdscr, row, 2, f"Attack Type: {attack_type}", curses.color_pair(1) if risk == "CRITICAL" else curses.color_pair(2))
        row += 2

        _draw_box(stdscr, row, 1, 10, w - 2, " BEHAVIORAL FEATURES ", 4)
        row += 1
        feature_labels = {
            "conn_rate": "Connection Rate",
            "unique_ports": "Unique Ports",
            "unique_hosts": "Unique Hosts",
            "avg_request_len": "Avg Request Len",
            "error_rate": "Error Rate",
            "special_char_ratio": "Special Chars",
            "burst_count": "Burst Count",
            "protocol_anomalies": "Protocol Anomalies",
        }
        for fname, label in feature_labels.items():
            if row >= h - 5:
                break
            val = features.get(fname, 0)
            bar, _ = _score_bar(min(val / max(1.0, 10.0), 1.0), 15)
            _safe_addstr(stdscr, row, 3, f"{label:<20} {val:>8.3f}  ", curses.color_pair(4))
            _safe_addstr(stdscr, row, 34, bar[:15], curses.color_pair(4))
            row += 1

        row += 1
        suggestions = self.ai.decision._generate_suggestions(score)
        if suggestions:
            _safe_addstr(stdscr, row, 2, "SUGGESTIONS:", curses.color_pair(5) | curses.A_BOLD)
            row += 1
            for s in suggestions:
                if row >= h - 3:
                    break
                _safe_addstr(stdscr, row, 4, f"• {s[:w-7]}", curses.color_pair(2))
                row += 1

        _safe_addstr(stdscr, h - 2, 2, "[u] Unblock IP | [ESC/s] Back to Suspicious", curses.color_pair(8) | curses.A_BOLD)

    def stop(self):
        self._running = False
