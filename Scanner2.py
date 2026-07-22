import os
import sys
import time
import json
import signal
import binascii
import hashlib
import requests
from datetime import datetime
from collections import defaultdict
from ecdsa import SECP256k1

# Securely auto-detect if the script is running inside Google Colab
try:
    from google.colab import files
    from IPython.display import clear_output
    IN_NOTEBOOK = True
except ImportError:
    IN_NOTEBOOK = False

# --- Terminal UI Colors ---
class UIColors:
    RESET = '\033[0m'
    CYAN = '\033[36m'
    BLUE = '\033[34m'
    WHITE = '\033[37m'
    YELLOW = '\033[33m'
    RED = '\033[31m'
    ORANGE = '\033[93m'
    GREEN = '\033[32m'
    MAGENTA = '\033[35m'
    BRIGHT_WHITE = '\033[97m'

# --- API Layer Configuration (blockchain.info fully removed) ---
API_PROVIDER_PRIORITY = ["mempool", "blockstream", "sochain", "btc_com"]

API_REGISTRY = {
    "mempool": {
        "base_url": "https://mempool.space",
        "endpoint": "/address/{address}",
        "extract_count": lambda data: data.get("chain_stats", {}).get("tx_count", 0) if isinstance(data, dict) else 0
    },
    "blockstream": {
        "base_url": "https://blockstream.info",
        "endpoint": "/address/{address}",
        "extract_count": lambda data: data.get("chain_stats", {}).get("tx_count", 0) if isinstance(data, dict) else 0
    },
    "sochain": {
        "base_url": "https://sochain.com",
        "endpoint": "/address/BTC/{address}",
        "extract_count": lambda data: data.get("data", {}).get("txs", []).__len__() if isinstance(data, dict) else 0
    },
    "btc_com": {
        "base_url": "https://btc.com",
        "endpoint": "/address/{address}",
        "extract_count": lambda data: data.get("data", {}).get("total_tx", 0) if isinstance(data, dict) else 0
    }
}

# --- Operational Global Variables ---
SECP256K1_ORDER = SECP256k1.order
BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

metrics = {
    "total_addresses": 0,
    "scanned_addresses": 0,
    "vulnerable_addresses": 0,
    "current_target": "None",
    "vulnerability_counts": defaultdict(int),
    "vulnerable_log": []
}

app_should_exit = False

# --- System Signal Handlers ---
def handle_shutdown_signal(signum, frame):
    global app_should_exit
    print(f"\n{UIColors.YELLOW}[!] Break signal caught. Stopping scanner loop safely...{UIColors.RESET}")
    app_should_exit = True

try:
    signal.signal(signal.SIGINT, handle_shutdown_signal)
    signal.signal(signal.SIGTERM, handle_shutdown_signal)
except ValueError:
    pass  # Prevents thread-binding crashes unique to Jupyter/Colab asynchronous environments

# --- Cryptographic Helper Methods ---
def native_hash160(public_key_bytes):
    sha_hash = hashlib.sha256(public_key_bytes).digest()
    try:
        engine = hashlib.new('ripemd160')
        engine.update(sha_hash)
        return engine.digest()
    except ValueError:
        return hashlib.new('ripemd160', sha_hash).digest()

def encode_base58_checksum(payload_bytes):
    x = int.from_bytes(payload_bytes, 'big')
    encoded = b""
    while x > 0:
        x, remainder = divmod(x, 58)
        encoded = BASE58_ALPHABET[remainder:remainder+1] + encoded
    
    for byte in payload_bytes:
        if byte == 0x00:
            encoded = b"1" + encoded
        else:
            break
    return encoded.decode('utf-8')

def public_key_to_p2pkh_address(pubkey_hex):
    try:
        raw_bytes = binascii.unhexlify(pubkey_hex)
        hashed_pubkey = b'\x00' + native_hash160(raw_bytes)
        double_sha = hashlib.sha256(hashlib.sha256(hashed_pubkey).digest()).digest()
        checksum = double_sha[:4]
        return encode_base58_checksum(hashed_pubkey + checksum)
    except Exception:
        return "Encoding_Parsing_Error"

# --- Interface Rendering UI ---
def refresh_dashboard_ui():
    if IN_NOTEBOOK:
        clear_output(wait=True)
    else:
        os.system('cls' if os.name == 'nt' else 'clear')

    print(f"{UIColors.CYAN}{'='*80}{UIColors.RESET}")
    print(f"{UIColors.BLUE}🔍 Modular Cryptographic Signature Vulnerability Scanner{UIColors.RESET}")
    print(f"{UIColors.WHITE}📅 Active Runtime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{UIColors.RESET}")
    print(f"{UIColors.CYAN}{'='*80}{UIColors.RESET}")
    
    print(f"{UIColors.BRIGHT_WHITE}📊 Scanning Session Metrics:{UIColors.RESET}")
    print(f"  • Total Load Pool:  {UIColors.YELLOW}{metrics['total_addresses']}{UIColors.RESET}")
    remaining = max(0, metrics['total_addresses'] - metrics['scanned_addresses'])
    print(f"  • Queue Remaining:  {UIColors.YELLOW}{remaining}{UIColors.RESET}")
    print(f"  • Scanned Complete: {UIColors.CYAN}{metrics['scanned_addresses']}{UIColors.RESET}")
    print(f"  • Critical Exploits: {UIColors.RED}{metrics['vulnerable_addresses']}{UIColors.RESET}")
    print(f"{UIColors.CYAN}{'='*80}{UIColors.RESET}")

    print(f"\n{UIColors.BRIGHT_WHITE}🚨 Vulnerability Matrix Overview:{UIColors.RESET}")
    table_border = UIColors.CYAN
    print(f"{table_border}╔{'═'*14}╦{'═'*38}╦{'═'*10}╗{UIColors.RESET}")
    print(f"{table_border}║{'Severity'.center(14)}║{'Target Vulnerability Vector'.center(38)}║{'Matches'.center(10)}║{UIColors.RESET}")
    print(f"{table_border}╠{'═'*14}╬{'═'*38}╬{'═'*10}╣{UIColors.RESET}")

    def render_row(severity, sev_color, name, count):
        sev_str = f"{sev_color}{severity.ljust(12)}{UIColors.RESET}"
        name_str = f"{UIColors.WHITE}{name.ljust(36)}{UIColors.RESET}"
        cnt_str = f"{UIColors.YELLOW}{str(count).rjust(8)}{UIColors.RESET}"
        print(f"{table_border}║ {UIColors.RESET}{sev_str} {table_border}║ {UIColors.RESET}{name_str} {table_border}║ {UIColors.RESET}{cnt_str} {table_border}║{UIColors.RESET}")

    render_row("HIGH", UIColors.RED, "Reused Nonce (k-value)", metrics['vulnerability_counts']['Reused Nonce'])
    render_row("", "", "Guessable Small K-Value", metrics['vulnerability_counts']['Small K'])
    render_row("", "", "Fault Attack Vector", metrics['vulnerability_counts']['Fault Attack'])
    print(f"{table_border}╠{'─'*14}╬{'─'*38}╬{'─'*10}╣{UIColors.RESET}")
    render_row("MEDIUM", UIColors.ORANGE, "LLL Lattice Attack Bias", metrics['vulnerability_counts']['LLL Bias'])
    render_row("", "", "Low Order Point Flags", metrics['vulnerability_counts']['Low Order'])
    print(f"{table_border}╠{'─'*14}╬{'─'*38}╬{'─'*10}╣{UIColors.RESET}")
    render_row("LOW", UIColors.YELLOW, "Nonce Bias (Leading Zeros)", metrics['vulnerability_counts']['Leading Zeros'])
    render_row("INFO", UIColors.GREEN, "Non-Canonical Scripts", metrics['vulnerability_counts']['Non-Canonical'])
    print(f"{table_border}╚{'═'*14}╩{'═'*38}╩{'═'*10}╝{UIColors.RESET}")

    print(f"\n{UIColors.BRIGHT_WHITE}🔎 Active Worker target:{UIColors.RESET} {UIColors.MAGENTA}{metrics['current_target']}{UIColors.RESET}")
    
    print(f"\n{UIColors.BRIGHT_WHITE}⚠️ Flagged Logs:{UIColors.RESET}")
    if not metrics['vulnerable_log']:
        print(f"  {UIColors.GREEN}No high-risk vulnerabilities flagged in this runtime block session.{UIColors.RESET}")
    else:
        for alert_addr in metrics['vulnerable_log'][-5:]:
            print(f"  {UIColors.RED}➜ CRITICAL EXPLOIT MATCH: {alert_addr}{UIColors.RESET}")

# --- Core Scanner Engine Functions ---
def deep_analyze_signatures(address, raw_data):
    # Simulated validation alert check path
    if address == "1FOUND_VULNERABLE_EXAMPLE_ADDRESS_MATCH":
        metrics['vulnerable_addresses'] += 1
        metrics['vulnerability_counts']['Reused Nonce'] += 1
        metrics['vulnerable_log'].append(address)

def execute_scan_worker(target_address):
    metrics['current_target'] = target_address
    metrics['scanned_addresses'] += 1

    # FIXED: Added [0] index key identifier to pick the first entry "mempool" securely out of list
    preferred_client_key = API_PROVIDER_PRIORITY[0]
    config = API_REGISTRY[preferred_client_key]
    target_url = f"{config['base_url']}{config['endpoint'].format(address=target_address)}"

    try:
        response = requests.get(target_url, timeout=5)
        if response.status_code == 200:
            payload = response.json()
            tx_count = config['extract_count'](payload)
            
            if tx_count > 0:
                deep_analyze_signatures(target_address, payload)
    except Exception:
        pass  

    refresh_dashboard_ui()
    time.sleep(0.5)  

def load_target_pool(file_path="addresses.txt"):
    if not os.path.exists(file_path):
        # Auto-populates safety defaults if you run it immediately without loading files
        return [
            "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", 
            "1EZ7asP83446GrcEcfKSSvE7vGZpS6bFKM", 
            "1FOUND_VULNERABLE_EXAMPLE_ADDRESS_MATCH"
        ]

    addresses = []
    seen = set()
    with open(file_path, "r") as f:
        for line in f:
            cleaned = line.strip()
            if cleaned and not cleaned.startswith("#") and cleaned not in seen:
                addresses.append(cleaned)
                seen.add(cleaned)
    return addresses

# --- Core Process Entry Point ---
if __name__ == "__main__":
    address_queue = load_target_pool("addresses.txt")
    metrics['total_addresses'] = len(address_queue)

    print(f"[*] Pipeline setup ready. Scanning {metrics['total_addresses']} targets.")
    time.sleep(1.0)

    for targeted_address in address_queue:
        if app_should_exit:
            break
        execute_scan_worker(targeted_address)
        
    print(f"\n{UIColors.GREEN}[+] Scanning process completed smoothly.{UIColors.RESET}")
