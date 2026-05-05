"""
TUI Dashboard for Pocket-Wall — simple 3-column layout.
Left: All connections | Middle: Blocked & Warned | Right: AI Analysis
"""

import curses
import time

SYM_BLOCK = "\u25cf"
SYM_WARN  = "\u25b2"
SYM_OK    = "\u2713"
SYM_LINE  = "\u2500"
SYM_VLINE = "\u2502"
SYM_UL    = "\u250c"
SYM_UR    = "\u2510"
SYM_LL    = "\u2514"
SYM_LR    = "\u2518"


def _safe(win, y, x, text, attr=0):
    h, w = win.getmaxyx()
    if y < 0 or y >= h or x < 0 or x >= w - 1:
        return
    try:
        win.addnstr(y, x, str(text), w - x - 1, attr)
    except curses.error:
        pass


def _hline(win, y, x, w, attr=0):
    try:
        for i in range(w):
            win.addch(y, x + i, SYM_LINE, attr)
    except curses.error:
        pass


class TUI:

    def __init__(self, ids_engine):
        self.ids = ids_engine
        self._running = True
        self._s1 = 0
        self._s2 = 0

    def run(self, stdscr):
        curses.curs_set(0)
        stdscr.nodelay(True)
        stdscr.timeout(400)

        curses.start_color()
        curses.use_default_colors()
        curses.init_pair(1, curses.COLOR_RED, -1)
        curses.init_pair(2, curses.COLOR_YELLOW, -1)
        curses.init_pair(3, curses.COLOR_GREEN, -1)
        curses.init_pair(4, curses.COLOR_CYAN, -1)
        curses.init_pair(5, curses.COLOR_MAGENTA, -1)
        curses.init_pair(6, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_GREEN)

        while self._running:
            try:
                stdscr.erase()
                h, w = stdscr.getmaxyx()
                if h < 8 or w < 40:
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
                    self._s1 = max(0, self._s1 - 1)
                elif k == curses.KEY_DOWN:
                    self._s1 += 1
                elif k == ord('p'):
                    self._s2 = max(0, self._s2 - 1)
                elif k == ord(';'):
                    self._s2 += 1
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
        _safe(scr, 1, 2, f"Total:{s.total}  Allowed:{s.allowed}  Blocked:{s.blocked}  Warned:{s.warned}", curses.color_pair(4) | curses.A_BOLD)
        _hline(scr, 2, 0, w, curses.color_pair(4))

        c1w = w // 3
        c2w = (w * 2) // 3
        top = 3
        ch = h - 7

        _safe(scr, top, 1, " Connections ", curses.color_pair(3) | curses.A_BOLD)
        _safe(scr, top, c1w + 1, " Blocked/Warned ", curses.color_pair(1) | curses.A_BOLD)
        _safe(scr, top, c2w + 1, " AI ", curses.color_pair(5) | curses.A_BOLD)
        for r in range(top + 1, top + ch + 1):
            try:
                scr.addch(r, c1w, SYM_VLINE, curses.color_pair(4))
                scr.addch(r, c2w, SYM_VLINE, curses.color_pair(4))
            except curses.error:
                pass

        self._col1(scr, top + 1, 1, c1w - 2, ch)
        self._col2(scr, top + 1, c1w + 2, c2w - c1w - 3, ch)
        self._col3(scr, top + 1, c2w + 2, w - c2w - 3, ch)

        fy = top + ch + 1
        _hline(scr, fy, 0, w, curses.color_pair(4))
        _safe(scr, fy + 1, 2, "[q]Quit [c]Clear [Up/Dn]Scroll conns [p/;]Scroll blocked", curses.color_pair(7) | curses.A_BOLD)
        geo = ", ".join(sorted(self.ids.blocked_countries)) or "None"
        _safe(scr, h - 1, 2, f"Geo:{geo}  Blocker:{self.ids.blocker.get_method()}  Threshold:{self.ids.threshold_block}%", curses.color_pair(5))

    def _col1(self, win, y, x, w, h):
        evts = list(self.ids.events)
        if not evts:
            _safe(win, y, x, "Waiting...", curses.color_pair(4))
            return
        start = min(self._s1, max(0, len(evts) - h))
        for i, ev in enumerate(evts[start:start + h]):
            if i >= h:
                break
            ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
            if ev.action == "BLOCK":
                sym, clr = SYM_BLOCK, curses.color_pair(1) | curses.A_BOLD
            elif ev.action == "WARN":
                sym, clr = SYM_WARN, curses.color_pair(2)
            else:
                sym, clr = SYM_OK, curses.color_pair(3)
            _safe(win, y + i, x, f"{ts} {sym} {ev.ip:<15} {ev.country:>3} {ev.score:>3}% {ev.reason[:w-28]}", clr)

    def _col2(self, win, y, x, w, h):
        items = [e for e in self.ids.events if e.action in ("BLOCK", "WARN")]
        if not items:
            _safe(win, y, x, "All clear", curses.color_pair(3))
            return
        items.reverse()
        start = min(self._s2, max(0, len(items) - h))
        for i, ev in enumerate(items[start:start + h]):
            if i >= h:
                break
            ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
            sym = SYM_BLOCK if ev.action == "BLOCK" else SYM_WARN
            clr = curses.color_pair(1) if ev.action == "BLOCK" else curses.color_pair(2)
            _safe(win, y + i, x, f"{ts} {sym} {ev.ip:<15} S:{ev.score} {ev.reason[:w-24]}", clr | curses.A_BOLD)

    def _col3(self, win, y, x, w, h):
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
        _safe(win, r, x, f"Threshold:{bl.get('threshold',0):.3f}  Mean:{bl.get('mean',0):.3f}", curses.color_pair(5))
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
