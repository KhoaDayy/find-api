import os
import sys
import time
import shutil
import ctypes
import ssl
import json
from http.server import HTTPServer, BaseHTTPRequestHandler
import threading

# ================= Configuration =================
HOSTS_FILE = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_BAK = r"C:\Windows\System32\drivers\etc\hosts.bak.sniffer"
LOG_FILE = "api_log.txt"
CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

DOMAINS_TO_HIJACK = [
    "h72.update.nieapps.com",
    "h72.update.netease.com",
    "h72-ms-prod.netease.com",
    "h72.fp.ps.netease.com",
    "h72naxx2gb-ms-prod.easebar.com",
    "unisdk.update.netease.com",
    "sdk.g.163.com",
    "sdkpass.163.com",
    "gw.163.com",
    "mpay.netease.com"
]

# ================= Helper Functions =================
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def mod_hosts():
    print("[*] Backing up and modifying hosts file...")
    if not os.path.exists(HOSTS_BAK):
        shutil.copy2(HOSTS_FILE, HOSTS_BAK)
        
    with open(HOSTS_FILE, 'r') as f:
        content = f.read()

    new_content = content
    added_count = 0
    for domain in DOMAINS_TO_HIJACK:
        line = f"127.0.0.1 {domain}"
        if line not in new_content:
            new_content += f"\n{line}"
            added_count += 1
            
    if added_count > 0:
        with open(HOSTS_FILE, 'w') as f:
            f.write(new_content)
        print(f"[+] Added {added_count} hijack entries to hosts file.")
        # Flush DNS cache so changes take effect
        os.system("ipconfig /flushdns >nul")
        print("[+] Flushed DNS cache.")
    else:
        print("[*] Hosts file already contains hijack entries.")

def restore_hosts():
    print("\n[*] Restoring original hosts file...")
    if os.path.exists(HOSTS_BAK):
        try:
            shutil.copy2(HOSTS_BAK, HOSTS_FILE)
            os.remove(HOSTS_BAK)
            os.system("ipconfig /flushdns >nul")
            print("[+] Hosts file restored.")
        except Exception as e:
            print(f"[!] Failed to restore hosts file: {e}")
    else:
        print("[*] No backup found, nothing to restore.")

# ================= Request Handler =================
class RequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass # Suppress default logging

    def do_request(self):
        client_ip = self.client_address[0]
        host = self.headers.get("Host", "UnknownHost")
        method = self.command
        path = self.path
        
        req_line = f"[{time.strftime('%H:%M:%S')}] {method} https://{host}{path} (from {client_ip})"
        print(f"\n\033[92m{req_line}\033[0m")
        
        # Log headers
        headers_str = ""
        for k, v in self.headers.items():
            headers_str += f"{k}: {v}\n"
        print("[HEADERS]\n" + headers_str.strip())
        
        # Log body
        content_length = int(self.headers.get('Content-Length', 0))
        body = b""
        if content_length > 0:
            body = self.rfile.read(content_length)
            
            # Try to decode string/json
            try:
                text_body = body.decode('utf-8')
                print("[PAYLOAD (Text)]\n" + text_body)
            except:
                print(f"[PAYLOAD (Binary)]\nHex: {body[:100].hex()}... (size={len(body)})")
        else:
            print("[PAYLOAD] (Empty)")
            
        print("-" * 50)
        
        # Log to file
        with open(LOG_FILE, 'a', encoding='utf-8') as f:
            f.write("\n" + "="*50 + "\n")
            f.write(req_line + "\n")
            f.write("[HEADERS]\n" + headers_str)
            if body:
                try:
                    f.write(f"[PAYLOAD]\n" + body.decode('utf-8') + "\n")
                except:
                    f.write(f"[PAYLOAD BINARY] {body[:200].hex()}...\n")

        import urllib.request
        import urllib.error
        import ssl
        import json
        import socket
        
        session_uid = self.headers.get("h72-ms-uid")
        if session_uid:
            try:
                with open("session.txt", "w", encoding="utf-8") as sf:
                    sf.write(session_uid)
                print(f"[SESSION UPDATED] Extracted new session: {session_uid}")
            except Exception as e:
                print(f"Failed to save session: {e}")

        # Resolve real IP using Google DNS over HTTPS to bypass local hosts file
        # We patch socket.getaddrinfo so urllib sends the correct SNI!
        try:
            doh_url = f"https://dns.google/resolve?name={host}"
            with urllib.request.urlopen(doh_url, timeout=5) as doh_resp:
                doh_data = json.loads(doh_resp.read())
                real_ip = doh_data['Answer'][-1]['data']
        except Exception as e:
            print(f"[!] DNS resolution failed for {host}: {e}")
            self.send_error(502, "Bad Gateway")
            return
            
        # Monkey patch socket.getaddrinfo temporarily for this thread
        orig_getaddrinfo = socket.getaddrinfo
        def patched_getaddrinfo(req_host, port, family=0, type=0, proto=0, flags=0):
            if req_host == host:
                return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, '', (real_ip, port))]
            return orig_getaddrinfo(req_host, port, family, type, proto, flags)
        
        socket.getaddrinfo = patched_getaddrinfo
        
        url = f"https://{host}{path}"
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        
        req_headers = {}
        for k, v in self.headers.items():
            if k.lower() not in ('content-length',):
                req_headers[k] = v
                
        try:
            req = urllib.request.Request(url, data=body if body else None, headers=req_headers, method=method)
            with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
                resp_body = response.read()
                self.send_response(response.status)
                for k, v in response.headers.items():
                    if k.lower() not in ('transfer-encoding', 'content-length', 'connection'):
                        self.send_header(k, v)
                self.send_header('Content-Length', str(len(resp_body)))
                self.send_header('Connection', 'close')
                self.end_headers()
                self.wfile.write(resp_body)
                
                print(f"[<- Response] {response.status} (len={len(resp_body)})")
                with open(LOG_FILE, 'a', encoding='utf-8') as f:
                    f.write(f"[<- Response] {response.status} (len={len(resp_body)})\n")
                    
        except urllib.error.HTTPError as e:
            try:
                resp_body = e.read()
                self.send_response(e.code)
                for k, v in e.headers.items():
                    if k.lower() not in ('transfer-encoding', 'content-length', 'connection'):
                        self.send_header(k, v)
                self.send_header('Content-Length', str(len(resp_body)))
                self.end_headers()
                self.wfile.write(resp_body)
                print(f"[<- Upstream Error {e.code}]")
            except:
                self.send_error(502, "Bad Gateway")
        except Exception as e:
            print(f"[!] Target unreachable/error: {e}")
            self.send_error(502, "Bad Gateway")
        finally:
            socket.getaddrinfo = orig_getaddrinfo

    def do_GET(self): self.do_request()
    def do_POST(self): self.do_request()
    def do_PUT(self): self.do_request()

# ================= Servers =================
def run_https_server():
    server_address = ('0.0.0.0', 443)
    httpd = HTTPServer(server_address, RequestHandler)
    
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)
    
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    print("[+] HTTPS Sniffer listening on port 443...")
    httpd.serve_forever()

def run_http_server():
    server_address = ('0.0.0.0', 80)
    httpd = HTTPServer(server_address, RequestHandler)
    print("[+] HTTP  Sniffer listening on port 80...")
    httpd.serve_forever()

# ================= Main =================
if __name__ == "__main__":
    if not is_admin():
        print("[*] Requesting Administrator privileges...")
        # Re-run the program with admin rights
        script_path = os.path.abspath(sys.argv[0])
        ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script_path}"', None, 1)
        if int(ret) <= 32:
            print("[!] Failed to elevate privileges (user canceled or error). Please run as Administrator manually.")
        sys.exit(0)

    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("[!] cert.pem or key.pem not found. Generating now...")
        os.system(f'python -c "from cryptography.hazmat.primitives import serialization; from cryptography.hazmat.primitives.asymmetric import rsa; from cryptography import x509; from cryptography.x509.oid import NameOID; from cryptography.hazmat.primitives import hashes; import datetime; key = rsa.generate_private_key(public_exponent=65537, key_size=2048); subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u\'netease.com\')]); cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(datetime.datetime.utcnow()).not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10)).sign(key, hashes.SHA256()); open(\'cert.pem\', \'wb\').write(cert.public_bytes(serialization.Encoding.PEM)); open(\'key.pem\', \'wb\').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))"')

    print("=" * 60)
    print("  Game API Sniffer - DNS Hijack + HTTPS Proxy (No SSL Pinning)")
    print("=" * 60 + "\n")

    print("[*] Please ensure you have manually added the domains to your hosts file.")
    print("    e.g., 127.0.0.1 h72.update.nieapps.com")
    print("          127.0.0.1 unisdk.update.netease.com")
    print("          ... etc")
    
    t1 = threading.Thread(target=run_https_server, daemon=True)
    t2 = threading.Thread(target=run_http_server, daemon=True)
    
    t1.start()
    t2.start()

    print("\n[*] Sniffer is running! Start the game and try to login.")
    print("[*] Press Ctrl+C to stop and restore hosts file.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[*] Caught Ctrl+C, shutting down...")
    finally:
        print("[+] Goodbye!")
