import socket, time, webbrowser, random, requests, logging
import argparse, hmac, hashlib, base64, re
from bs4 import BeautifulSoup  # New dependency for HTML parsing

# Logging setup
logging.basicConfig(filename='cli.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Parse args
arg = argparse.ArgumentParser()
arg.add_argument("--target", default="10.1.2.90", help="Server IP (default: 10.1.2.90)")
arg.add_argument("--port", type=int, default=8080, help="HTTP port (default: 8080)")
arg.add_argument("--timeout", type=int, default=10, help="Timeout")
arg.add_argument("--key", default="shared_secret_key", help="HMAC key (should match server)")
arg.add_argument("--retries", type=int, default=2, help="Connection retries (default: 3)")
arg.add_argument("--show-denied", action="store_true", help="Show access denied page in browser when denied")
cfg = arg.parse_args()

SRV_IP = cfg.target
SECRET_PORT = cfg.port
TIMEOUT = cfg.timeout
KEY = cfg.key.encode()
RETRIES = cfg.retries
SHOW_DENIED = cfg.show_denied

def gen_hmac(data):
    return base64.b64encode(hmac.new(KEY, data.encode(), hashlib.sha256).digest()).decode()

def get_seq():
    retries = RETRIES
    while retries > 0:
        try:
            print(f"[*] Connecting to server at {SRV_IP}:5000 (Attempt {RETRIES - retries + 1}/{RETRIES})...")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(TIMEOUT)
                sock.connect((SRV_IP, 5000))
                
                response = sock.recv(1024).decode()
                
                # Check for unauthorized status
                if response == "UNAUTHORIZED":
                    print("[!] Your IP is not authorized to access this server.")
                    logging.warning("IP not authorized by server.")
                    # Try to access HTTP server directly to get the access denied page
                    if SHOW_DENIED:
                        print("[*] Opening access denied page in browser...")
                        check_http(expect_denied=True)
                    return []
                
                # Parse sequence if allowed
                try:
                    seq = response.split(",")
                    print("[*] Got sequence:", seq)
                    logging.info(f"Received sequence: {seq}")
                    return [int(p) for p in seq]
                except ValueError:
                    print(f"[!] Invalid response from server: {response}")
                    logging.error(f"Invalid server response: {response}")
                    return []
        except socket.timeout:
            retries -= 1
            if retries > 0:
                print(f"[!] Connection timed out. Retrying ({retries} attempts left)...")
                time.sleep(2)
            else:
                print("[!] Failed to get sequence: all connection attempts timed out")
        except ConnectionRefusedError:
            print(f"[!] Connection refused at {SRV_IP}:5000. Is the server running?")
            return []
        except Exception as e:
            print(f"[!] Failed to get sequence: {e}")
            return []
    return []

def send_knocks(seq):
    if not seq or len(seq) != 3:
        print("[!] Bad sequence.")
        return
    
    for p in seq:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                msg = f"{p}:{gen_hmac(str(p))}"
                sock.sendto(msg.encode(), (SRV_IP, 5001))
                print(f"[+] Knocked on {p}")
                time.sleep(random.uniform(0.3, 1.0))
        except Exception as e:
            print(f"[!] Knock failed: {e}")
            return
    
    print("[*] Knock sequence complete. Checking access...")
    time.sleep(2)
    check_http()

def check_http(expect_denied=False):
    url = f"http://{SRV_IP}:{SECRET_PORT}"
    try:
        res = requests.get(url, timeout=5)
        if res.status_code == 200:
            print(f"[✓] Access granted: {url}")
            webbrowser.open(url)
        else:
            print(f"[X] HTTP server blocked access. Status code: {res.status_code}")
            
            # Handle the access denied page
            if res.status_code == 403:
                if expect_denied or SHOW_DENIED:
                    print("[*] Opening access denied page in browser...")
                    
                    # Extract and display details from the access denied page
                    try:
                        soup = BeautifulSoup(res.text, 'html.parser')
                        ip = soup.find(id='client-ip').text.strip()
                        time_denied = soup.find(id='current-time').text.strip()
                        print(f"[!] Access denied for IP: {ip} at {time_denied}")
                    except Exception:
                        pass
                    
                    # Save the HTML content to a temporary file and open in browser
                    with open('access_denied_response.html', 'w') as f:
                        f.write(res.text)
                    webbrowser.open('file://' + os.path.abspath('access_denied_response.html'))
            
    except Exception as e:
        print(f"[!] No HTTP response: {e}")

if __name__ == "__main__":
    print(f"[*] Port knocking client connecting to {SRV_IP}")
    
    # Add import for os if needed
    import os
    
    seq = get_seq()
    if seq:
        send_knocks(seq)
    else:
        print("[!] Could not retrieve knock sequence. Access denied.")