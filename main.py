import socket
import threading
from firewall import is_blocked, check_flood, log

HOST = "0.0.0.0"
PORT = 3128

active_connections = {}
conn_lock = threading.Lock()
MAX_CONN = 10


def handle_client(client_sock, client_addr):
    ip = client_addr[0]
    client_sock.settimeout(5)

    with conn_lock:
        active_connections[ip] = active_connections.get(ip, 0) + 1
        if active_connections[ip] > MAX_CONN:
            log.warning(f"[{ip}] too many connections")
            client_sock.close()
            return

    try:
        if check_flood(ip):
            client_sock.send(b"HTTP/1.1 429 Too Many Requests\r\n\r\n")
            return

        request = client_sock.recv(4096).decode(errors="ignore")
        if not request:
            return

        parts = request.split("\n")[0].split()
        if len(parts) < 2:
            return

        method, url = parts[0], parts[1]

        host = url if method == "CONNECT" else url.split("/")[2]

        if is_blocked(host):
            log.info(f"[{ip}] {host} BLOCKED")
            client_sock.send(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return

        log.info(f"[{ip}] {host} ALLOWED")

        if method == "CONNECT":
            dest_host, dest_port = host.split(":") if ":" in host else (host, 443)
            server = socket.create_connection((dest_host, int(dest_port)))
            client_sock.send(b"HTTP/1.1 200 OK\r\n\r\n")
            pipe(client_sock, server)

        else:
            dest_host = host.split(":")[0]
            dest_port = int(host.split(":")[1]) if ":" in host else 80
            server = socket.create_connection((dest_host, dest_port))
            server.sendall(request.encode())
            pipe(client_sock, server)

    except Exception as e:
        log.error(f"[{ip}] error: {e}")

    finally:
        client_sock.close()
        with conn_lock:
            active_connections[ip] -= 1


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

    threading.Thread(target=forward, args=(b, a), daemon=True).start()
    forward(a, b)


def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(200)

    log.info(f"Proxy running on {PORT}")

    while True:
        c, addr = server.accept()
        threading.Thread(target=handle_client, args=(c, addr), daemon=True).start()


if __name__ == "__main__":
    main()