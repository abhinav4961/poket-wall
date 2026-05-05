import os
import time
import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
from threading import Lock

class GUI:
    def __init__(self, ids_engine):
        self.ids = ids_engine
        self.root = tk.Tk()
        self.root.title("🛡️ Pocket-Wall IDS")
        self.root.geometry("900x600")
        self.root.protocol("WM_DELETE_WINDOW", self.stop)
        
        self._running = True
        self._lock = Lock()
        
        self._setup_ui()
        self._update_loop()

    def _setup_ui(self):
        style = ttk.Style()
        style.theme_use("clam")
        
        # Header
        header_frame = ttk.Frame(self.root, padding=10)
        header_frame.pack(fill=tk.X)
        
        title_lbl = ttk.Label(header_frame, text="🛡️ POCKET-WALL IDS", font=("Arial", 16, "bold"))
        title_lbl.pack(side=tk.LEFT)
        
        self.stats_lbl = ttk.Label(header_frame, text="", font=("Arial", 12))
        self.stats_lbl.pack(side=tk.RIGHT)
        
        # Controls Frame
        ctrl_frame = ttk.Frame(self.root, padding=5)
        ctrl_frame.pack(fill=tk.X)
        
        ttk.Button(ctrl_frame, text="Geo-Block Config", command=self._show_geo_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl_frame, text="Thresholds", command=self._show_threshold_config).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl_frame, text="Blocked IPs", command=self._show_blocked_ips).pack(side=tk.LEFT, padx=5)
        ttk.Button(ctrl_frame, text="Clear Alerts", command=self.ids.clear_alerts).pack(side=tk.LEFT, padx=5)
        
        # AI Button (Highlight)
        ai_btn = tk.Button(ctrl_frame, text="✨ AI Insights", bg="#4CAF50", fg="white", font=("Arial", 10, "bold"), command=self._show_ai_popup)
        ai_btn.pack(side=tk.RIGHT, padx=5)

        # Main Content PanedWindow
        paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Left Panel (Live Traffic)
        left_frame = ttk.LabelFrame(paned, text="▶ LIVE TRAFFIC")
        paned.add(left_frame, weight=1)
        
        cols_traffic = ("Time", "IP", "Country", "Action", "Score")
        self.tree_traffic = ttk.Treeview(left_frame, columns=cols_traffic, show="headings", height=15)
        for col in cols_traffic:
            self.tree_traffic.heading(col, text=col)
            self.tree_traffic.column(col, width=100)
        
        vsb_traffic = ttk.Scrollbar(left_frame, orient="vertical", command=self.tree_traffic.yview)
        self.tree_traffic.configure(yscrollcommand=vsb_traffic.set)
        self.tree_traffic.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb_traffic.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Right Panel (Alerts)
        right_frame = ttk.LabelFrame(paned, text="!! ALERTS")
        paned.add(right_frame, weight=1)
        
        cols_alerts = ("Time", "IP", "Action", "Score", "Reason")
        self.tree_alerts = ttk.Treeview(right_frame, columns=cols_alerts, show="headings", height=15)
        for col in cols_alerts:
            self.tree_alerts.heading(col, text=col)
            self.tree_alerts.column(col, width=80)
        self.tree_alerts.column("Reason", width=150)
        
        vsb_alerts = ttk.Scrollbar(right_frame, orient="vertical", command=self.tree_alerts.yview)
        self.tree_alerts.configure(yscrollcommand=vsb_alerts.set)
        self.tree_alerts.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vsb_alerts.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Add tag configurations for colors
        self.tree_traffic.tag_configure("BLOCK", foreground="red")
        self.tree_traffic.tag_configure("WARN", foreground="orange")
        self.tree_traffic.tag_configure("ALLOW", foreground="green")
        
        self.tree_alerts.tag_configure("BLOCK", foreground="red")
        self.tree_alerts.tag_configure("WARN", foreground="orange")
        
        # Status Bar
        self.status_lbl = ttk.Label(self.root, text="Ready", padding=5, relief=tk.SUNKEN, anchor=tk.W)
        self.status_lbl.pack(side=tk.BOTTOM, fill=tk.X)

    def _update_loop(self):
        if not self._running:
            return
        
        # Update Stats
        s = self.ids.stats
        self.stats_lbl.config(text=f"Total: {s.total} | Blocked: {s.blocked} | Warned: {s.warned} | Clean: {s.allowed}")
        
        # Update Geo string in status bar
        geo_str = ", ".join(sorted(self.ids.blocked_countries)) if self.ids.blocked_countries else "None"
        self.status_lbl.config(text=f"Geo-Blocked: {geo_str}  |  Thresholds: Block>={self.ids.threshold_block} Warn>={self.ids.threshold_warn}")
        
        # Update Traffic
        with self._lock:
            # We just replace the whole tree contents for simplicity
            for item in self.tree_traffic.get_children():
                self.tree_traffic.delete(item)
            
            # Show last 50 events
            events = list(self.ids.events)[-50:]
            for ev in events:
                ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
                self.tree_traffic.insert("", tk.END, values=(ts, ev.ip, ev.country, ev.action, f"{ev.score}%"), tags=(ev.action,))
            if events:
                self.tree_traffic.yview_moveto(1.0)
            
            # Update Alerts
            for item in self.tree_alerts.get_children():
                self.tree_alerts.delete(item)
            
            alerts = list(self.ids.alerts)[-50:]
            for ev in alerts:
                ts = time.strftime("%H:%M:%S", time.localtime(ev.timestamp))
                self.tree_alerts.insert("", 0, values=(ts, ev.ip, ev.action, f"{ev.score}%", ev.reason), tags=(ev.action,))
        
        self.root.after(1000, self._update_loop)

    def _show_geo_config(self):
        code = simpledialog.askstring("Geo-Block", "Enter 2-letter country code to Add (e.g. CN)\nOr prefix with '-' to Remove (e.g. -CN):", parent=self.root)
        if code:
            code = code.strip().upper()
            if code.startswith("-"):
                self.ids.remove_country(code[1:])
                messagebox.showinfo("Geo-Block", f"Removed {code[1:]}", parent=self.root)
            else:
                self.ids.add_country(code.lstrip("+"))
                messagebox.showinfo("Geo-Block", f"Added {code.lstrip('+')}", parent=self.root)

    def _show_threshold_config(self):
        top = tk.Toplevel(self.root)
        top.title("Thresholds")
        top.geometry("300x150")
        
        ttk.Label(top, text="Block Threshold (0-100):").pack(pady=5)
        b_var = tk.IntVar(value=self.ids.threshold_block)
        ttk.Entry(top, textvariable=b_var).pack()
        
        ttk.Label(top, text="Warn Threshold (0-100):").pack(pady=5)
        w_var = tk.IntVar(value=self.ids.threshold_warn)
        ttk.Entry(top, textvariable=w_var).pack()
        
        def save():
            try:
                self.ids.threshold_block = max(0, min(100, b_var.get()))
                self.ids.threshold_warn = max(0, min(100, w_var.get()))
                self.ids.save_config()
                top.destroy()
            except ValueError:
                pass
                
        ttk.Button(top, text="Save", command=save).pack(pady=10)

    def _show_blocked_ips(self):
        top = tk.Toplevel(self.root)
        top.title("Blocked IPs")
        top.geometry("400x300")
        
        listbox = tk.Listbox(top)
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        def refresh():
            listbox.delete(0, tk.END)
            for ip in self.ids.get_blocked_ips():
                listbox.insert(tk.END, ip)
                
        refresh()
        
        def unblock():
            sel = listbox.curselection()
            if sel:
                ip = listbox.get(sel[0])
                self.ids.unblock_ip(ip)
                refresh()
                
        ttk.Button(top, text="Unblock Selected", command=unblock).pack(pady=5)

    def _show_ai_popup(self):
        top = tk.Toplevel(self.root)
        top.title("✨ AI Insights")
        top.geometry("500x400")
        
        stats = self.ids.get_ai_stats()
        
        if "error" in stats:
            ttk.Label(top, text="AI Engine is not available.", font=("Arial", 12)).pack(pady=20)
            return
            
        # Top Stats
        ttk.Label(top, text="AI Telemetry", font=("Arial", 14, "bold")).pack(pady=5)
        
        frame_stats = ttk.Frame(top)
        frame_stats.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(frame_stats, text=f"Analyzed Windows: {stats.get('analyzed_windows', 0)}").grid(row=0, column=0, sticky=tk.W, padx=10)
        ttk.Label(frame_stats, text=f"Anomalies Detected: {stats.get('anomalies_detected', 0)}").grid(row=0, column=1, sticky=tk.W, padx=10)
        ttk.Label(frame_stats, text=f"Active Suspects: {stats.get('active_suspects', 0)}").grid(row=1, column=0, sticky=tk.W, padx=10)
        
        # Alerts
        ttk.Label(top, text="Recent AI Alerts:", font=("Arial", 12, "bold")).pack(pady=5, anchor=tk.W, padx=10)
        
        cols = ("Time", "IP", "Reason", "Confidence")
        tree = ttk.Treeview(top, columns=cols, show="headings", height=10)
        for col in cols:
            tree.heading(col, text=col)
            tree.column(col, width=100)
            
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        alerts = self.ids.get_ai_alerts(limit=20)
        for al in alerts:
            ts = time.strftime("%H:%M:%S", time.localtime(al.get("timestamp", time.time())))
            tree.insert("", tk.END, values=(ts, al.get("ip"), al.get("reason"), f"{al.get('confidence', 0):.2f}"))

    def stop(self):
        self._running = False
        self.root.destroy()

    def run(self):
        self.root.mainloop()

if __name__ == "__main__":
    pass
