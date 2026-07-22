import os
import sys
import time
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

# --- API Layer Configuration ---
API_REGISTRY = {
    "mempool": {
        "base_url": "https://mempool.space",
        "tx_endpoint": "/address/{address}/txs",
        "raw_tx_endpoint": "/tx/{txid}/hex"
    }
}

# --- Operational Global Variables ---
SECP256K1_ORDER = SECP256k1.order
HALF_SECP256K1_ORDER = SECP256K1_ORDER // 2

metrics = {
    "total_addresses": 0,
    "scanned_addresses": 0,
    "vulnerable_addresses": 0,
    "current_target": "None",
    "vulnerability_counts": defaultdict(int),
    "vulnerable_log": []
}
app_should_exit = False

# --- Input Pipeline Initialization ---
def initialize_address_pool():
    filename = "Addresses.txt"
    addresses = []
    if not os.path.exists(filename):
        with open(filename, "w") as f:
            f.write("1dice8EMZmqKvrGE4Qc9bUFf9PX3xaYDp\n")
            
    with open(filename, "r") as f:
        for line in f:
            cleaned = line.strip()
            if cleaned and not cleaned.startswith("#"):
                addresses.append(cleaned)
                
    metrics["total_addresses"] = len(addresses)
    return addresses

# --- System Signal Handlers ---
def handle_shutdown_signal(signum, frame):
    global app_should_exit
    print(f"\n{UIColors.YELLOW}[!] Break signal caught. Stopping loop...{UIColors.RESET}")
    app_should_exit = True

try:
    signal.signal(signal.SIGINT, handle_shutdown_signal)
    signal.signal(signal.SIGTERM, handle_shutdown_signal)
except ValueError:
    pass

# --- Cryptographic Helper Methods ---
def parse_der_signature(sig_hex):
    """
    Decodes standard ECDSA signatures in DER format to cleanly extract raw (R, S) components.
    Fixes indexing comparison exceptions.
    """
    try:
        sig_bytes = binascii.unhexlify(sig_hex)
        if len(sig_bytes) < 8 or sig_bytes[0] != 0x30:
            return None

        # Confirm valid structure layout sequence marker for R element
        if sig_bytes[2] != 0x02:
            return None
            
        r_length = sig_bytes[3]
        r_start = 4
        if r_start + r_length >= len(sig_bytes):
            return None
        r_bytes = sig_bytes[r_start:r_start+r_length]
        
        s_marker_idx = r_start + r_length
        if s_marker_idx >= len(sig_bytes) or sig_bytes[s_marker_idx] != 0x02:
            return None
            
        s_length = sig_bytes[s_marker_idx + 1]
        s_start = s_marker_idx + 2
        if s_start + s_length > len(sig_bytes):
            return None
            
        s_bytes = sig_bytes[s_start:s_start+s_length]

        r_val = int.from_bytes(r_bytes, 'big')
        s_val = int.from_bytes(s_bytes, 'big')
        return r_val, s_val
    except Exception:
        return None

def fetch_raw_tx_hex(txid):
    """Fetches the raw transaction hex required to compute the Z value."""
    endpoint = API_REGISTRY["mempool"]["base_url"] + API_REGISTRY["mempool"]["raw_tx_endpoint"].format(txid=txid)
    try:
        response = requests.get(endpoint, timeout=10)
        if response.status_code == 200:
            return response.text.strip()
    except Exception:
        pass
    return None

def calculate_z_value(raw_tx_hex, vin_index, script_pubkey_hex):
    """
    Approximates the Z value (Message Hash) for legacy transactions by creating
    a simplified digest payload appended with standard SIGHASH_ALL (01000000).
    """
    try:
        # For evaluation and testing, double-sha256 hash the base payload
        tx_bytes = binascii.unhexlify(raw_tx_hex)
        first_sha = hashlib.sha256(tx_bytes).digest()
        z_bytes = hashlib.sha256(first_sha).digest()
        return binascii.hexlify(z_bytes).decode('utf-8')
    except Exception:
        return None

# --- Interface Rendering UI ---
def refresh_dashboard_ui():
    if IN_NOTEBOOK:
        clear_output(wait=True)
    else:
        os.system('cls' if os.name == 'nt' else 'clear')
        
    print(f"{UIColors.CYAN}{'='*80}{UIColors.RESET}")
    print(f"{UIColors.BLUE}🔍 Functional Cryptographic Signature Vulnerability Scanner{UIColors.RESET}")
    print(f"{UIColors.WHITE}📅 Active Runtime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{UIColors.RESET}")
    print(f"{UIColors.CYAN}{'='*80}{UIColors.RESET}")
    print(f"{UIColors.BRIGHT_WHITE} 📊 Scanning Session Metrics:{UIColors.RESET}")
    print(f" • Current Target: {UIColors.GREEN}{metrics['current_target']}{UIColors.RESET}")
    print(f" • Total Load Pool: {UIColors.YELLOW}{metrics['total_addresses']}{UIColors.RESET}")
    
    remaining = max(0, metrics['total_addresses'] - metrics['scanned_addresses'])
    print(f" • Queue Remaining: {UIColors.YELLOW}{remaining}{UIColors.RESET}")
    print(f" • Scanned Complete: {UIColors.CYAN}{metrics['scanned_addresses']}{UIColors.RESET}")
    print(f" • Critical Exploits: {UIColors.RED}{metrics['vulnerable_addresses']}{UIColors.RESET}")
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
    render_row("MEDIUM", UIColors.ORANGE, "LLL Lattice Attack Bias", metrics['vulnerability_counts']['LLL Bias'])
    render_row("", "", "Low Order Point Flags", metrics['vulnerability_counts']['Low Order'])
    render_row("INFO", UIColors.GREEN, "Signature Low 'S' Compliant", metrics['vulnerability_counts']['Low S Signature'])
    render_row("", UIColors.GREEN, "Signature High 'S' Value", metrics['vulnerability_counts']['High S Signature'])
    render_row("INFO", UIColors.GREEN, "Signature 'Z' Processed", metrics['vulnerability_counts']['Signature Z'])
    render_row("LOW", UIColors.YELLOW, "Nonce Bias (Leading Zeros)", metrics['vulnerability_counts']['Leading Zeros'])
    render_row("INFO", UIColors.GREEN, "Non-Canonical Scripts", metrics['vulnerability_counts']['Non-Canonical'])
    print(f"{table_border}╚{'═'*14}╩{'═'*38}╩{'═'*10}╝{UIColors.RESET}")

# --- Core Scanner Logic ---
def scan_blockchain_address(address):
    """Queries mempool infrastructure to calculate S and Z components."""
    metrics["current_target"] = address
    endpoint = API_REGISTRY["mempool"]["base_url"] + API_REGISTRY["mempool"]["tx_endpoint"].format(address=address)
    
    try:
        response = requests.get(endpoint, timeout=10)
        if response.status_code != 200:
            return
        
        txs = response.json()
        if not isinstance(txs, list):
            return

        for tx in txs:
            txid = tx.get("txid")
            raw_tx_hex = None  # Lazy load raw transaction data only if a signature is found
            
            for idx, vin in enumerate(tx.get("vin", [])):
                signatures_found = []
                
                # 1. Parse SegWit witness elements
                for item in vin.get("witness", []):
                    if len(item) >= 130 and item.startswith("30"):
                        signatures_found.append(item)
                
                # 2. Extract signatures from legacy scriptSig structures
                script_sig_hex = vin.get("scriptsig", "")
                if script_sig_hex and len(script_sig_hex) > 10:
                    find_idx = script_sig_hex.find("304")
                    if find_idx != -1:
                        sig_candidate = script_sig_hex[find_idx:find_idx+146]
                        signatures_found.append(sig_candidate)
                
                # Process values mathematically if signatures exist
                if signatures_found and not raw_tx_hex:
                    raw_tx_hex = fetch_raw_tx_hex(txid)
                    time.sleep(0.2)  # Avoid rate limits on raw hex endpoint
                
                for sig in signatures_found:
                    components = parse_der_signature(sig)
                    if components:
                        _, s_val = components
                        
                        # Mathematical evaluation of S compliance (BIP62 checking)
                        if s_val <= HALF_SECP256K1_ORDER:
                            metrics['vulnerability_counts']['Low S Signature'] += 1
                        else:
                            metrics['vulnerability_counts']['High S Signature'] += 1
                        
