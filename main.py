import socket
import threading
from firewall import is_blocked, check_flood, log

HOST = "0.0.0.0"
PORT = 3128

# Track active connections per IP
active_connections = {}
conn_lock = threading.Lock()
MAX_CONNECTIONS_PER_IP = 10


def handle_client(client_sock, client_addr):
    ip = client_addr[0]

    # Set timeout to avoid hanging
    client_sock.settimeout(5)

    # Track active connections
    with conn_lock:
        active_connections[ip] = active_connections.get(ip, 0) + 1

        if active_connections[ip] > MAX_CONNECTIONS_PER_IP:
            log.warning(f"[{ip}] TOO MANY CONNECTIONS")
            client_sock.close()
            active_connections[ip] -= 1
            return

    try:
        # Flood check (HTTP-level)
        if check_flood(ip):
            log.warning(f"[{ip}] FLOOD BLOCKED")
            client_sock.send(b"HTTP/1.1 429 Too Many Requests\r\n\r\nBlocked\r\n")
            return

        request = client_sock.recv(4096).decode(errors="ignore")
        if not request:
            return

        # Safe parsing
        lines = request.split("\n")
        if len(lines) == 0:
            return

        first_line = lines[0].strip().split()
        if len(first_line) < 2:
            return

        method = first_line[0]
        url = first_line[1]

        # Extract host safely
        host = ""
        if method == "CONNECT":
            host = url
        else:
            try:
                host = url.split("/")[2]
            except:
                return

        # Blocklist check
        if is_blocked(host):
            log.info(f"[{ip}] {method} {host} -> BLOCKED")
            client_sock.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Pi-Wall\r\n")
            return

        log.info(f"[{ip}] {method} {host} -> ALLOWED")

        # HTTPS tunnel
        if method == "CONNECT":
            dest_host, dest_port = host.split(":") if ":" in host else (host, 443)

            server_sock = socket.create_connection((dest_host, int(dest_port)), timeout=5)
            client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")

            pipe(client_sock, server_sock)

        # HTTP proxy
        else:
            dest_host = host.split(":")[0]
            dest_port = int(host.split(":")[1]) if ":" in host else 80

            server_sock = socket.create_connection((dest_host, dest_port), timeout=5)
            server_sock.sendall(request.encode())

            pipe(client_sock, server_sock)

    except socket.timeout:
        log.warning(f"[{ip}] timeout")
    except Exception as e:
        log.error(f"[{ip}] error: {e}")

    finally:
        try:
            client_sock.close()
        except:
            pass

        # Decrement active connections
        with conn_lock:
            active_connections[ip] -= 1
            if active_connections[ip] <= 0:
                del active_connections[ip]


def pipe(a, b):
    def forward(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.sendall(data)
        except:
            pass
        finally:
            try:
                dst.close()
            except:
                pass

    t = threading.Thread(target=forward, args=(b, a), daemon=True)
    t.start()
    forward(a, b)


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server.bind((HOST, PORT))
    server.listen(200)

    log.info(f"Pi-Wall proxy running on {HOST}:{PORT}")

    while True:
        client_sock, client_addr = server.accept()
        t = threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True)
        t.start()


if __name__ == "__main__":
    main()