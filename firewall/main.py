import argparse
import curses
import socket
import sys
import threading
from firewall import is_blocked, check_flood, log
from ids import IDSEngine, load_api_key, test_api_key
from tui import TUI

HOST = "0.0.0.0"
PORT = 3128

active_connections = {}
conn_lock = threading.Lock()
MAX_CONN = 10

ids_engine: IDSEngine | None = None


def _recv_full_request(sock):
    data = b""
    sock.settimeout(10)
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
            if b"\r\n\r\n" in data:
                break
    except socket.timeout:
        pass
    return data.decode(errors="ignore")


def _ids_check_async(ip, request=""):
    if not ids_engine:
        return
    try:
        ids_engine.record_traffic(ip, request=request, request_len=len(request))
        verdict = ids_engine.check_ip(ip)
        if verdict == "BLOCK":
            log.warning(f"[IDS] {ip} BLOCKED (background analysis)")
    except Exception as e:
        log.error(f"[IDS] background check error: {e}")


def handle_client(client_sock, client_addr):
    ip = client_addr[0]
    try:
        client_sock.settimeout(5)

        if check_flood(ip):
            try:
                client_sock.send(b"HTTP/1.1 429 Too Many Requests\r\n\r\n")
            finally:
                client_sock.close()
            return

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

        request = _recv_full_request(client_sock)
        if not request:
            return

        first_line = request.split("\n")[0].split()
        if len(first_line) < 2:
            return

        method, url = first_line[0], first_line[1]

        if method == "CONNECT":
            host = url
        else:
            try:
                host = url.split("/")[2]
            except IndexError:
                return

        host_no_port = host.split(":")[0]

        if is_blocked(host_no_port):
            log.info(f"[{ip}] {host_no_port} BLOCKED")
            try:
                client_sock.send(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            except Exception:
                pass
            return

        log.info(f"[{ip}] {host_no_port} ALLOWED")

        threading.Thread(target=_ids_check_async, args=(ip, request), daemon=True).start()

        if method == "CONNECT":
            parts = host.split(":")
            dest_host = parts[0]
            try:
                dest_port = int(parts[1]) if len(parts) > 1 else 443
            except ValueError:
                dest_port = 443
            log.info(f"[{ip}] CONNECT {dest_host}:{dest_port}")
            server = socket.create_connection((dest_host, dest_port), timeout=15)
            client_sock.settimeout(None)
            try:
                client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            except Exception:
                server.close()
                return
            _pipe_bidirectional(client_sock, server)
        else:
            dest_host = host_no_port
            dest_port = int(host.split(":")[1]) if ":" in host else 80
            log.info(f"[{ip}] HTTP {dest_host}:{dest_port}")
            server = socket.create_connection((dest_host, dest_port), timeout=10)
            try:
                server.sendall(request.encode())
            except Exception:
                server.close()
                return
            _proxy_http_response(client_sock, server, ip)

    except socket.timeout:
        log.warning(f"[{ip}] connection timed out")
    except socket.gaierror as e:
        log.error(f"[{ip}] DNS resolution failed: {e}")
        try:
            client_sock.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception:
            pass
    except ConnectionRefusedError as e:
        log.error(f"[{ip}] connection refused: {e}")
        try:
            client_sock.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception:
            pass
    except Exception as e:
        log.error(f"[{ip}] error: {e}")
        try:
            client_sock.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception:
            pass
    finally:
        client_sock.close()
        with conn_lock:
            if active_connections.get(ip, 0) > 0:
                active_connections[ip] -= 1


def _proxy_http_response(client_sock, server, ip):
    try:
        while True:
            chunk = server.recv(4096)
            if not chunk:
                break
            client_sock.sendall(chunk)
    except Exception as e:
        log.error(f"[{ip}] proxy error: {e}")
    finally:
        server.close()


def _pipe_bidirectional(a, b):
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
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    t1 = threading.Thread(target=forward, args=(a, b), daemon=True)
    t2 = threading.Thread(target=forward, args=(b, a), daemon=True)
    t1.start()
    t2.start()
    t1.join(timeout=60)
    t2.join(timeout=5)


def start_proxy():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(200)
    log.info(f"Proxy running on {PORT}")

    while True:
        c, addr = server.accept()
        log.info(f"[{addr[0]}:{addr[1]}] new connection")
        threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()


def main():
    global ids_engine

    parser = argparse.ArgumentParser(description="Pocket-Wall Firewall + IDS")
    parser.add_argument("--tui", action="store_true", help="Launch with TUI dashboard (press [a] for AI view)")
    parser.add_argument("--web", action="store_true", help="Launch with REST API on port 5000")
    parser.add_argument("--no-ids", action="store_true", help="Disable IDS engine")
    parser.add_argument("--test-ids", metavar="IP", nargs="?", const="1.1.1.1", help="Test AbuseIPDB API against a public IP and exit")
    args = parser.parse_args()

    if args.test_ids:
        test_api_key(args.test_ids)
        sys.exit(0)

    if not args.no_ids:
        api_key = load_api_key()
        if api_key:
            ids_engine = IDSEngine(api_key)
            block_method = ids_engine.blocker.get_method()
            ai_status = "AI ready" if ids_engine.ai else "AI disabled"
            log.info(f"[IDS] Engine initialised (block: {block_method}, {ai_status})")
            log.info("[IDS] Analysis runs in background — does not block traffic")
        else:
            log.warning("[IDS] No API key found in .env — IDS disabled")

    if args.web:
        from api import start_api_server
        proxy_thread = threading.Thread(target=start_proxy, daemon=True)
        proxy_thread.start()
        log.info("[WEB] Starting REST API on port 5000")
        start_api_server(ids_engine)

    elif args.tui:
        if ids_engine is None:
            print("ERROR: IDS engine required for TUI. Check your .env file for abuse_ipdb_api_key")
            sys.exit(1)

        proxy_thread = threading.Thread(target=start_proxy, daemon=True)
        proxy_thread.start()

        try:
            tui = TUI(ids_engine)
            curses.wrapper(tui.run)
        except KeyboardInterrupt:
            pass
        finally:
            log.info("Shutting down...")
    else:
        start_proxy()


if __name__ == "__main__":
    main()
