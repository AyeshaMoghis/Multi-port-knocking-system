import socket, threading, random, hmac, hashlib, base64
import http.server, socketserver, logging

# Logging setup
logfmt = '%(asctime)s - %(levelname)s - %(message)s'
logging.basicConfig(filename='knock_server.log', level=logging.INFO, format=logfmt)

# Configuration
SECRET_PORT = 8080
HMAC_KEY = b"shared_secret_key"
clients = {}

def gen_seq():
    return [random.randint(4000, 9000) for _ in range(3)]

def verify_knock(port, recv_hmac):
    exp = base64.b64encode(hmac.new(HMAC_KEY, str(port).encode(), hashlib.sha256).digest()).decode()
    return hmac.compare_digest(exp, recv_hmac)

def start_http():
    with socketserver.TCPServer(("", SECRET_PORT), http.server.SimpleHTTPRequestHandler) as srv:
        logging.info("HTTP server running on port %d", SECRET_PORT)
        print(f"[Server] HTTP server running on port {SECRET_PORT}")
        srv.serve_forever()

def handle_knock(ip, port, recv_hmac):
    if ip not in clients:
        logging.warning("Unknown IP tried knocking: %s", ip)
        return
    seq = clients[ip]
    if port == seq[0] and verify_knock(port, recv_hmac):
        clients[ip] = seq[1:]
        if not clients[ip]:  # sequence complete
            logging.info("%s completed knock sequence.", ip)
            print(f"[Server] {ip} completed knock sequence! Access granted.")
            clients.pop(ip)
    else:
        logging.warning("%s sent wrong knock. Resetting.", ip)
        clients.pop(ip)

def listen_knocks():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", 5001))  # Listen on all interfaces for UDP
        print("[Server] Listening for knock sequences on UDP 5001...")
        while True:
            data, addr = sock.recvfrom(1024)
            ip = addr[0]
            try:
                port, recv_hmac = data.decode().split(":")
                handle_knock(ip, int(port), recv_hmac)
            except ValueError:
                logging.error("Malformed knock from %s", ip)

def assign_seq():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv_sock:
        srv_sock.bind(("0.0.0.0", 5000))  # Listen on all interfaces for TCP
        srv_sock.listen()
        print("[Server] Waiting for clients on TCP 5000...")
        while True:
            cli_sock, addr = srv_sock.accept()
            ip = addr[0]
            seq = gen_seq()
            clients[ip] = seq
            cli_sock.send(",".join(map(str, seq)).encode())
            cli_sock.close()
            logging.info("Assigned sequence %s to %s", seq, ip)
            print(f"[Server] Assigned sequence {seq} to {ip}")

if __name__ == "__main__":
    threading.Thread(target=start_http, daemon=True).start()  # Start HTTP server
    threading.Thread(target=assign_seq, daemon=True).start()  # Start TCP listener
    listen_knocks()  # Start UDP knock listener