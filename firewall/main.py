import argparse
import curses
import socket
import sys
import threading
from firewall import is_blocked, check_flood, log
from ids import IDSEngine, load_api_key
from tui import TUI

HOST = "0.0.0.0"
PORT = 3128

active_connections = {}
conn_lock = threading.Lock()
MAX_CONN = 10

# Global IDS engine — initialised in main()
ids_engine: IDSEngine | None = None
# Global TUI ref for log bridging
tui_ref: TUI | None = None


def start_api(engine):
    """Start the REST API in a thread."""
    from api import start_api_server
    start_api_server(engine)


def handle_client(client_sock, client_addr):
    ip = client_addr[0]
    client_sock.settimeout(5)

    # --- IDS check ---
    if ids_engine:
        verdict = ids_engine.check_ip(ip)
        if verdict == "BLOCK":
            log.warning(f"[IDS] {ip} BLOCKED (threat score / geo)")
            try:
                client_sock.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Pocket-Wall IDS\r\n")
            finally:
                client_sock.close()
            return

    # --- Flood check BEFORE touching connection counter ---
    if check_flood(ip):
        try:
            client_sock.send(b"HTTP/1.1 429 Too Many Requests\r\n\r\n")
        finally:
            client_sock.close()
        return

    # --- Increment, reject if over limit ---
    with conn_lock:
        active_connections[ip] = active_connections.get(ip, 0) + 1
        over_limit = active_connections[ip] > MAX_CONN

    if over_limit:
        log.warning(f"[{ip}] too many connections ({active_connections[ip]})")
        try:
            client_sock.send(b"HTTP/1.1 429 Too Many Requests\r\n\r\n")
        finally:
            client_sock.close()
            with conn_lock:
                active_connections[ip] -= 1
        return

    try:
        request = client_sock.recv(4096).decode(errors="ignore")
        if not request:
            return

        first_line = request.split("\n")[0].split()
        if len(first_line) < 2:
            return

        method, url = first_line[0], first_line[1]

        # Parse target host
        if method == "CONNECT":
            host = url  # host:port
        else:
            # http://host/path  →  split off scheme, take netloc
            try:
                host = url.split("/")[2]
            except IndexError:
                return

        # Strip port for blocklist check
        host_no_port = host.split(":")[0]

        if is_blocked(host_no_port):
            log.info(f"[{ip}] {host_no_port} BLOCKED")
            client_sock.send(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return

        log.info(f"[{ip}] {host_no_port} ALLOWED")

        if method == "CONNECT":
            dest_host, dest_port = (host.split(":") + ["443"])[:2]
            server = socket.create_connection((dest_host, int(dest_port)), timeout=10)
            client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        else:
            dest_host = host_no_port
            dest_port = int(host.split(":")[1]) if ":" in host else 80
            server = socket.create_connection((dest_host, dest_port), timeout=10)
            server.sendall(request.encode())

        pipe(client_sock, server)

    except Exception as e:
        log.error(f"[{ip}] error: {e}")
    finally:
        client_sock.close()
        with conn_lock:
            if active_connections.get(ip, 0) > 0:
                active_connections[ip] -= 1


def pipe(a, b):
    """Bidirectional relay. Blocks until BOTH directions are done."""
    done = threading.Event()

    def forward(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except Exception:
            pass
        finally:
            # Signal the other direction to stop by closing the write-end
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass
            done.set()

    t = threading.Thread(target=forward, args=(b, a), daemon=True)
    t.start()
    forward(a, b)
    done.wait()   # wait for the reverse direction before returning
    t.join(timeout=2)


def start_proxy():
    """Start the proxy server (runs forever)."""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(200)
    log.info(f"Proxy running on {PORT}")

    while True:
        c, addr = server.accept()
        threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()


def main():
    global ids_engine, tui_ref

    parser = argparse.ArgumentParser(description="Pocket-Wall Firewall + IDS")
    parser.add_argument("--tui", action="store_true", help="Launch with TUI dashboard")
    parser.add_argument("--web", action="store_true", help="Launch with React web dashboard (API on :5000)")
    parser.add_argument("--no-ids", action="store_true", help="Disable IDS engine")
    args = parser.parse_args()

    # Load API key and init IDS
    if not args.no_ids:
        api_key = load_api_key()
        if api_key:
            ids_engine = IDSEngine(api_key)
            log.info("[IDS] Engine initialised with AbuseIPDB integration")
        else:
            log.warning("[IDS] No API key found in .env — IDS disabled")

    if args.web:
        # Start proxy in background thread
        proxy_thread = threading.Thread(target=start_proxy, daemon=True)
        proxy_thread.start()

        # Start Flask API (blocks main thread)
        log.info("[WEB] Starting REST API on port 5000")
        start_api(ids_engine)

    elif args.tui:
        if ids_engine is None:
            print("ERROR: IDS engine required for TUI. Check your .env file for abuse_ipdb_api_key")
            sys.exit(1)

        # Start proxy in background thread
        proxy_thread = threading.Thread(target=start_proxy, daemon=True)
        proxy_thread.start()

        # Run TUI in main thread
        tui = TUI(ids_engine)
        tui_ref = tui
        try:
            curses.wrapper(tui.run)
        except KeyboardInterrupt:
            pass
        finally:
            log.info("Shutting down...")
    else:
        # Classic mode — just run proxy with log output
        start_proxy()


if __name__ == "__main__":
    main()