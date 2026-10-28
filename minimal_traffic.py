import socket
import http.client
import time

TARGET_HOST = "example.com"

def generate_https_traffic(count=5):
    """Gera tráfego mínimo para a porta 443 (Q1)."""
    print(f"[*] Gerando {count} conexões HTTPS para {TARGET_HOST}:443...")
    for _ in range(count):
        try:
            conn = http.client.HTTPSConnection(TARGET_HOST, timeout=2)
            conn.request("GET", "/")
            conn.getresponse().read()
            conn.close()
        except Exception:
            pass
        time.sleep(0.2)

def generate_bruteforce_traffic(count=51):
    """Gera 51 SYNs para a porta 22 (Q2: limiar > 50)."""
    print(f"[*] Gerando {count} SYNs para {TARGET_HOST}:22...")
    for _ in range(count):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((TARGET_HOST, 22))
            s.close()
        except Exception:
            pass
        time.sleep(0.01)

def generate_portscan_traffic(ports=None):
    """Tenta conectar a 11 portas distintas (Q3: limiar > 10)."""
    if ports is None:
        ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 8080]
    print(f"[*] Realizando escaneamento em {len(ports)} portas de {TARGET_HOST}...")
    for port in ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            s.connect((TARGET_HOST, port))
            s.close()
        except Exception:
            pass
        time.sleep(0.05)

if __name__ == "__main__":
    print("=== Gerador de tráfego mínimo para cmp230 ===")
    
    generate_https_traffic(count=5)
    generate_bruteforce_traffic(count=51)
    generate_portscan_traffic()
    print("=== Tráfego mínimo gerado. Verifique a saída do pipeline. ===")
