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
tui_ref: TUI | None = None


def start_api(engine):
    from api import start_api_server
    start_api_server(engine)


def _recv_full_request(sock):
    """Read complete HTTP request (headers only, no body for proxy purposes)."""
    data = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
        if b"\r\n\r\n" in data:
            break
    return data.decode(errors="ignore")


def handle_client(client_sock, client_addr):
    ip = client_addr[0]
    client_sock.settimeout(5)

    if ids_engine:
        ids_engine.record_traffic(ip)
        verdict = ids_engine.check_ip(ip)
        if verdict == "BLOCK":
            log.warning(f"[IDS] {ip} BLOCKED (threat score / geo / AI)")
            try:
                client_sock.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Pocket-Wall IDS\r\n")
            finally:
                client_sock.close()
            return

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

    try:
        request = _recv_full_request(client_sock)
        if not request:
            return

        first_line = request.split("\n")[0].split()
        if len(first_line) < 2:
            if ids_engine:
                ids_engine.record_anomaly(ip)
            return

        method, url = first_line[0], first_line[1]

        if ids_engine:
            ids_engine.record_traffic(ip, request=request, request_len=len(request))

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
            if ids_engine:
                ids_engine.record_error(ip)
            client_sock.send(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return

        log.info(f"[{ip}] {host_no_port} ALLOWED")

        if method == "CONNECT":
            dest_host, dest_port = (host.split(":") + ["443"])[:2]
            try:
                dest_port = int(dest_port)
            except ValueError:
                dest_port = 443
            server = socket.create_connection((dest_host, dest_port), timeout=15)
            client_sock.settimeout(None)
            client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            _pipe_bidirectional(client_sock, server)
        else:
            dest_host = host_no_port
            dest_port = int(host.split(":")[1]) if ":" in host else 80
            server = socket.create_connection((dest_host, dest_port), timeout=10)
            server.sendall(request.encode())
            _proxy_http_response(client_sock, server, ip)

    except socket.timeout:
        log.warning(f"[{ip}] connection timed out")
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
    """Forward HTTP response from server to client. Handles chunked and content-length."""
    try:
        response = b""
        while True:
            chunk = server.recv(4096)
            if not chunk:
                break
            response += chunk
            client_sock.sendall(chunk)
            if _response_complete(response):
                break
    except Exception as e:
        log.error(f"[{ip}] proxy error: {e}")
    finally:
        server.close()


def _response_complete(data: bytes) -> bool:
    """Check if we've received a complete HTTP response."""
    try:
        header_end = data.find(b"\r\n\r\n")
        if header_end == -1:
            return False

        headers = data[:header_end].decode("ascii", errors="ignore").lower()

        content_length = None
        for line in headers.split("\r\n"):
            if line.startswith("content-length:"):
                content_length = int(line.split(":")[1].strip())
                break

        if content_length is not None:
            body = data[header_end + 4:]
            return len(body) >= content_length

        if "transfer-encoding: chunked" in headers:
            return data.endswith(b"0\r\n\r\n")

        if "connection: close" in headers:
            return False

        return len(data) > header_end + 4
    except Exception:
        return False


def _pipe_bidirectional(a, b):
    """Bidirectional pipe for HTTPS (CONNECT) tunnels."""
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
        threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()


def main():
    global ids_engine, tui_ref

    parser = argparse.ArgumentParser(description="Pocket-Wall Firewall + IDS")
    parser.add_argument("--tui", action="store_true", help="Launch with TUI dashboard")
    parser.add_argument("--web", action="store_true", help="Launch with React web dashboard (API on :5000)")
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
            log.info(f"[IDS] Engine initialised (block: {ids_engine.blocker.get_method()})")
        else:
            log.warning("[IDS] No API key found in .env — IDS disabled")

    if args.web:
        proxy_thread = threading.Thread(target=start_proxy, daemon=True)
        proxy_thread.start()
        log.info("[WEB] Starting REST API on port 5000")
        start_api(ids_engine)

    elif args.tui:
        if ids_engine is None:
            print("ERROR: IDS engine required for TUI. Check your .env file for abuse_ipdb_api_key")
            sys.exit(1)

        proxy_thread = threading.Thread(target=start_proxy, daemon=True)
        proxy_thread.start()

        tui = TUI(ids_engine)
        tui_ref = tui
        try:
            curses.wrapper(tui.run)
        except KeyboardInterrupt:
            pass
        finally:
            log.info("Shutting down...")
    else:
        start_proxy()


if __name__ == "__main__":
    main()
