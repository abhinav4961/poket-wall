import socket
import threading
from firewall import is_blocked, check_flood, log

HOST = "0.0.0.0"
PORT = 3128

def handle_client(client_sock, client_addr):
    ip = client_addr[0]
    try:
        # Flood check
        if check_flood(ip):
            log.warning(f"[{ip}] FLOOD BLOCKED")
            client_sock.send(b"HTTP/1.1 429 Too Many Requests\r\n\r\nBlocked by Pi-Wall: flood detected\r\n")
            return

        request = client_sock.recv(4096).decode(errors="ignore")
        if not request:
            return

        first_line = request.split("\n")[0]
        method = first_line.split(" ")[0]
        url    = first_line.split(" ")[1]

        # Parse host
        if method == "CONNECT":
            host = url
        else:
            host = url.split("/")[2] if "/" in url else url

        # Blacklist check
        if is_blocked(host):
            log.info(f"[{ip}] {method} {host} -> BLOCKED")
            client_sock.send(b"HTTP/1.1 403 Forbidden\r\n\r\nBlocked by Pi-Wall\r\n")
            return

        log.info(f"[{ip}] {method} {host} -> ALLOWED")

        # HTTPS tunnel
        if method == "CONNECT":
            dest_host, dest_port = host.split(":") if ":" in host else (host, 443)
            server_sock = socket.create_connection((dest_host, int(dest_port)), timeout=10)
            client_sock.send(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            pipe(client_sock, server_sock)

        # Plain HTTP
        else:
            dest_host = host.split(":")[0]
            dest_port = int(host.split(":")[1]) if ":" in host else 80
            server_sock = socket.create_connection((dest_host, dest_port), timeout=10)
            server_sock.send(request.encode())
            pipe(client_sock, server_sock)

    except Exception as e:
        log.error(f"[{ip}] error: {e}")
    finally:
        client_sock.close()

def pipe(a, b):
    """Forward bytes between two sockets until one closes."""
    def forward(src, dst):
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                dst.send(data)
        except:
            pass
        finally:
            try: dst.close()
            except: pass

    t = threading.Thread(target=forward, args=(b, a), daemon=True)
    t.start()
    forward(a, b)

def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((HOST, PORT))
    server.listen(100)
    log.info(f"Pi-Wall proxy listening on {HOST}:{PORT}")

    while True:
        client_sock, client_addr = server.accept()
        t = threading.Thread(target=handle_client, args=(client_sock, client_addr), daemon=True)
        t.start()

if __name__ == "__main__":
    main()