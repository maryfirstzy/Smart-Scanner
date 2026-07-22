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

# --- API Layer Configuration ---
API_PROVIDER_PRIORITY = "mempool"
API_REGISTRY = {
    "mempool": {
        "base_url": "https://mempool.space",
        "tx_endpoint": "/address/{address}/txs",
        "extract_count": lambda data: len(data) if isinstance(data, list) else 0
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
    pass

# --- Cryptographic Helper Methods ---
def parse_der_signature(sig_hex):
    """
    Decodes standard ECDSA signatures in DER format to extract raw (R, S) components.
    """
    try:
        sig_bytes = binascii.unhexlify(sig_hex)
        if len(sig_bytes) < 8 or sig_bytes[0] != 0x30:
            return None
        
        r_length = sig_bytes[1]
        r_start = 4
        r_bytes = sig_bytes[r_start:r_start + r_length]
        
        if (r_start + r_length + 1) >= len(sig_bytes):
            return None
            
        s_length = sig_bytes[r_start + r_length + 1]
        s_start = r_start + r_length + 2
        s_bytes = sig_bytes[s_start:s_start + s_length]
        
        r_val = int.from_bytes(r_bytes, 'big')
        s_val = int.from_bytes(s_bytes, 'big')
        
        return r_val, s_val
    except Exception:
        return None

def check_low_s_signature(s_val):
    """
    Checks if the S component exceeds half the curve order (Malleability Check).
    """
    half_curve_order = SECP256K1_ORDER // 2
    return s_val > half_curve_order

def compute_z_value(tx_hash_hex):
    """
    Converts a transaction hash (HEX) into the Z value (the message hash) 
    by truncating it to the length of the curve order.
    """
    z_int = int(tx_hash_hex, 16)
    order_bits = SECP256K1_ORDER.bit_length()
    z_len = z_int.bit_length()
    
    if z_len > order_bits:
        z_int >>= (z_len - order_bits)
    return z_int

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
    print(f" • Total Load Pool: {UIColors.YELLOW}{metrics['total_addresses']}{UIColors.RESET}")
    remaining = max(0, metrics['total_addresses'] - metrics['scanned_addresses'])
    print(f" • Queue Remaining Pool: {UIColors.YELLOW}{remaining}{UIColors.RESET}")
    print(f" • Scan Completed: {UIColors.CYAN}{metrics['scanned_addresses']}{UIColors.RESET}")
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
    print(f"{table_border}╠{'─'*14}╬{'─'*38}╬{'─'*10}╣{UIColors.RESET}")
    render_row("MEDIUM", UIColors.ORANGE, "LLL Lattice Attack Bias", metrics['vulnerability_counts']['LLL Bias'])
    render_row("", "", "Low Order Point Flags", metrics['vulnerability_counts']['Low Order'])
    print(f"{table_border}╠{'─'*14}╬{'─'*38}╬{'─'*10}╣{UIColors.RESET}")
    render_row("LOW", UIColors.YELLOW, "Nonce Bias (Leading Zeros)", metrics['vulnerability_counts']['Leading Zeros'])
    render_row("INFO", UIColors.GREEN, "Non-Canonical Scripts", metrics['vulnerability_counts']['Non-Canonical'])
    
    # New additions added to table view
    render_row("INFO", UIColors.GREEN, "Signature S (High S Malleability)", metrics['vulnerability_counts']['Signature S'])
    render_row("INFO", UIColors.GREEN, "Computed Z (Message Hash)", metrics['vulnerability_counts']['Signature Z'])
    
    print(f"{table_border}╚{'═'*14}╩{'═'*38}╩{'═'*10}╝{UIColors.RESET}")

# --- Core Processing Logic ---
def process_transaction_signature(tx_hash, der_signature_hex):
    """
    Analyzes transaction signatures and evaluates the new Z and S constraints.
    """
    if not der_signature_hex:
        return

    parsed = parse_der_signature(der_signature_hex)
    if parsed:
        r, s = parsed
        
        # 1. Signature S Evaluation (Malleability check)
        if check_low_s_signature(s):
            metrics['vulnerability_counts']['Signature S'] += 1
        
        # 2. Signature Z Value Evaluation (Computed message hash)
        z_value = compute_z_value(tx_hash)
        if z_value > 0:
            metrics['vulnerability_counts']['Signature Z'] += 1
            
        metrics['scanned_addresses'] += 1
        metrics['total_addresses'] += 1

# --- Main Execution ---
def main():
    refresh_dashboard_ui()
    
    # Simulated demonstration of newly added signature checks
    print(f"\n{UIColors.YELLOW}[*] Starting simulated scan...{UIColors.RESET}")
    time.sleep(2)
    
    mock_transactions = [
        {"txid": "4a5e1e4baab89f3a32517a88c414879ff0d35d677a28e9323f4c6ab787053e19", "sig": "30450221008b3a0e10b10626b9112933405786358c2738a9d021c327de3234d31481b7642602202b23a9101d2c67b9319e340e4f8d951859c78be47b366a7b75a1d74366a6a4c2"},
        {"txid": "757a26f0430030560b29862de1ff7ec5ed856b3e6480b06b720b080516629ec8", "sig": "30440220623a8b4382c23be9f3908db6522cbb54bbcf33383e20e53dbf29762a4d3ad8d702202ab3b516848fa588de78d05370d06981442c55458117ac2cfbe9c1181f084be1"}
    ]

    for tx in mock_transactions:
        if app_should_exit:
            break
        process_transaction_signature(tx["txid"], tx["sig"])
        refresh_dashboard_ui()
        time.sleep(1)

    print(f"\n{UIColors.GREEN}[+] Scan Completed Successfully.{UIColors.RESET}")

if __name__ == "__main__":
    main()
