"""
TUI Dashboard — Blocked Connections + AI Analysis
Simple 2-panel layout, auto-refresh.
"""

import curses
import time

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

def _vline(win, y, x, h, attr=0):
    for r in range(y, y + h):
        try:
            win.addch(r, x, "\u2502", attr)
        except curses.error:
            pass

class TUI:
    def __init__(self, ids_engine):
        self.ids = ids_engine
        self._running = True
        self._sb = 0

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
        curses.init_pair(8, curses.COLOR_WHITE, curses.COLOR_RED)

        while self._running:
            try:
                stdscr.erase()
                h, w = stdscr.getmaxyx()
                if h < 6 or w < 30:
                    _safe(stdscr, 0, 0, "Terminal too small", curses.A_BOLD)
                    stdscr.refresh()
                    if stdscr.getch() == ord('q'):
                        self._running = False
                    continue
                self._draw(stdscr, h, w)
                stdscr.refresh()
                k = stdscr.getch()
                if k == ord('q'):
                    self._running = False
                elif k == curses.KEY_UP:
                    self._sb = max(0, self._sb - 1)
                elif k == curses.KEY_DOWN:
                    self._sb += 1
                elif k == ord('c'):
                    self.ids.clear_alerts()
            except curses.error:
                pass
            except KeyboardInterrupt:
                self._running = False

    def _draw(self, scr, h, w):
        s = self.ids.stats
        now = time.strftime("%H:%M:%S")

        _safe(scr, 0, 0, f" Pocket-Wall  |  {now}".ljust(w), curses.color_pair(6) | curses.A_BOLD)
        _safe(scr, 1, 2, f"Total:{s.total}  Blocked:{s.blocked}  Warned:{s.warned}  Allowed:{s.allowed}", curses.color_pair(4) | curses.A_BOLD)
        _line(scr, 2, 0, w, curses.color_pair(4))

        mid = w // 2
        top = 3
        ch = h - 7

        _safe(scr, top, 1, " Blocked Connections ", curses.color_pair(1) | curses.A_BOLD)
        _safe(scr, top, mid + 1, " AI Analysis ", curses.color_pair(5) | curses.A_BOLD)
        _vline(scr, top, mid, ch + 1, curses.color_pair(4))

        self._col_blocks(scr, top + 1, 1, mid - 2, ch)
        self._col_ai(scr, top + 1, mid + 2, w - mid - 3, ch)

        fy = top + ch + 1
        _line(scr, fy, 0, w, curses.color_pair(4))
        _safe(scr, fy + 1, 2, "[q]Quit [c]Clear [Up/Dn]Scroll", curses.color_pair(7) | curses.A_BOLD)
        geo = ", ".join(sorted(self.ids.blocked_countries)) or "None"
        _safe(scr, h - 1, 2, f"Geo:{geo}  Blocker:{self.ids.blocker.get_method()}  Threshold:{self.ids.threshold_block}%", curses.color_pair(5))

    def _col_blocks(self, win, y, x, w, h):
        items = [e for e in self.ids.events if e.action in ("BLOCK", "WARN")]
        if not items:
            _safe(win, y, x, "All clear", curses.color_pair(3))
            return
        items.reverse()
        start = min(self._sb, max(0, len(items) - h))
        for i, ev in enumerate(items[start:start + h]):
            if i >= h:
                break
            ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
            sym = "\u25cf" if ev.action == "BLOCK" else "\u25b2"
            clr = curses.color_pair(1) if ev.action == "BLOCK" else curses.color_pair(2)
            _safe(win, y + i, x, f"{ts} {sym} {ev.ip:<15} S:{ev.score} {ev.reason[:w-28]}", clr | curses.A_BOLD)

    def _col_ai(self, win, y, x, w, h):
        ai = getattr(self.ids, 'ai', None)
        r = y
        if not ai:
            _safe(win, r, x, "AI disabled", curses.color_pair(1) | curses.A_BOLD)
            return
        st = ai.get_ai_stats()
        bl = st.get('baseline', {})
        susp = ai.get_suspicious_ips()
        alrts = ai.get_alerts(5)

        _safe(win, r, x, f"Model:{'ON' if st.get('model_loaded') else 'OFF'}  Alerts:{st.get('total_alerts',0)}", curses.color_pair(4) | curses.A_BOLD)
        r += 1
        _safe(win, r, x, f"Threshold:{bl.get('threshold',0):.3f}  Mean:{bl.get('mean',0):.3f}  Std:{bl.get('std',0):.3f}", curses.color_pair(5))
        r += 1

        if susp:
            _safe(win, r, x, f"Suspicious:{len(susp)}", curses.color_pair(1) | curses.A_BOLD)
            r += 1
            for ip, sc in sorted(susp.items(), key=lambda s: s[1], reverse=True)[:4]:
                if r >= y + h - 1:
                    break
                rl = "CRIT" if sc >= 0.85 else "HIGH" if sc >= 0.7 else "MED" if sc >= 0.5 else "LOW"
                cl = curses.color_pair(1) if sc >= 0.7 else curses.color_pair(2)
                bar = "\u2588" * int(sc * 12) + "\u2591" * (12 - int(sc * 12))
                _safe(win, r, x, f"  {ip:<14} {bar} {sc:.2f} {rl}", cl)
                r += 1
        else:
            _safe(win, r, x, "No suspicious IPs", curses.color_pair(3))
            r += 1

        if alrts and r < y + h - 1:
            r += 1
            _safe(win, r, x, "AI Alerts:", curses.color_pair(5) | curses.A_BOLD)
            r += 1
            for a in reversed(alrts[-3:]):
                if r >= y + h:
                    break
                ts = time.strftime("%H:%M", time.localtime(a.get('timestamp', 0)))
                v = a.get('verdict', '?')[0]
                _safe(win, r, x, f"  {ts} {v} {a.get('ip','?'):<14} {a.get('score',0):.2f}", curses.color_pair(4))
                r += 1
