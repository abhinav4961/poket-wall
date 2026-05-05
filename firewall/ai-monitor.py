"""
Lightweight AI Monitor — reads AI stats and shows them in terminal.
Does NOT start proxy. Queries API or reads state directly.
"""

import json
import os
import time
import urllib.request

API_URL = "http://localhost:5000"

def fmt(ts):
    return time.strftime("%H:%M:%S", time.localtime(ts))

def main():
    print("=== Pocket-Wall AI Monitor ===")
    print(f"API: {API_URL}")
    print("Refreshing every 5s (Ctrl+C to stop)\n")

    while True:
        try:
            os.system('clear')
            print("=== Pocket-Wall AI Monitor ===")
            print(f"Updated: {time.strftime('%H:%M:%S')}\n")

            # AI Stats
            with urllib.request.urlopen(f"{API_URL}/api/ai-stats", timeout=2) as r:
                ai = json.loads(r.read())

            bl = ai.get("baseline", {})
            print(f"Model: {'Loaded' if ai.get('model_loaded') else 'Not loaded'}")
            print(f"Trees: {ai.get('tree_count', 0)}  |  Analyses run: {ai.get('analyses_run', 0)}")
            print(f"Baseline: mean={bl.get('mean',0):.3f}  std={bl.get('std',0):.3f}  threshold={bl.get('threshold',0):.3f}")
            print(f"Total AI Alerts: {ai.get('total_alerts', 0)}\n")

            # Suspicious IPs
            try:
                with urllib.request.urlopen(f"{API_URL}/api/ai-ip?ip=0.0.0.0", timeout=2) as r:
                    pass
            except Exception:
                pass

            # Recent events
            with urllib.request.urlopen(f"{API_URL}/api/events?limit=20", timeout=2) as r:
                events = json.loads(r.read())

            if events:
                print("Recent Connections:")
                for e in events[-10:]:
                    icon = "●" if e["action"] == "BLOCK" else "▲" if e["action"] == "WARN" else "✓"
                    print(f"  {fmt(e['timestamp'])} {icon} {e['ip']:<16} {e['country']}  {e['score']}%  {e['reason']}")

            print("\n[Press Ctrl+C to exit]")
            time.sleep(5)

        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"Error: {e} (is the API running?)")
            time.sleep(3)

if __name__ == "__main__":
    main()
