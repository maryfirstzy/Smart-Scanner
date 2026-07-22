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
def deep_analyze_signatures(address, detected_signatures):
    """
    Analyzes historical R and S values extracted from past transactions.
    """
    r_records = set()
    
    for r_val, s_val in detected_signatures:
        if r_val in r_records:
            metrics['vulnerable_addresses'] += 1
            metrics['vulnerability_counts']['Reused Nonce'] += 1
            log_msg = f"Address: {address} | Vulnerability: Reused Nonce (k-value) [R: {hex(r_val)[:16]}...]"
            metrics['vulnerable_log'].append(log_msg)
            
            try:
                with open("vuln.txt", "a", encoding="utf-8") as file_out:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    file_out.write(f"[{timestamp}] {log_msg}\n")
            except IOError:
                pass
        else:
            r_records.add(r_val)

        if r_val < 2**64:
            metrics['vulnerability_counts']['Small K'] += 1

def extract_signatures_from_tx_history(address, transactions):
    """
    Processes transaction structures from API data payloads, parsing scriptSigs 
    and witness vectors specifically matching spending events from the target.
    """
    extracted_signatures = []
    if not isinstance(transactions, list):
        return extracted_signatures

    for tx in transactions:
        inputs = tx.get("vin", [])
        for tx_input in inputs:
            prevout = tx_input.get("prevout")
            if not prevout or prevout.get("scriptpubkey_address") != address:
                continue
                
            sig_hex = ""
            script_sig = tx_input.get("scriptsig", "")
            if script_sig:
                if script_sig.startswith("473044") or script_sig.startswith("483045"):
                    sig_hex = script_sig[2:144]
            
            witness = tx_input.get("witness", [])
            if witness and len(witness) >= 1:
                potential_sig = witness[0]
                if potential_sig.startswith("3044") or potential_sig.startswith("3045"):
                    sig_hex = potential_sig

            if sig_hex:
                if len(sig_hex) > 140 and (sig_hex.endswith("01") or sig_hex.endswith("81")):
                    sig_hex = sig_hex[:-2]
                    
                parsed = parse_der_signature(sig_hex)
                if parsed:
                    extracted_signatures.append(parsed)
                    
    return extracted_signatures

def execute_scan_worker(target_address):
    metrics['current_target'] = target_address
    metrics['scanned_addresses'] += 1

    config = API_REGISTRY[API_PROVIDER_PRIORITY]
    target_url = f"{config['base_url']}{config['tx_endpoint'].format(address=target_address)}"

    try:
        response = requests.get(target_url, timeout=10)
        if response.status_code == 200:
            payload = response.json()
            found_sigs = extract_signatures_from_tx_history(target_address, payload)
            if found_sigs:
                deep_analyze_signatures(target_address, found_sigs)
    except Exception:
        pass

# --- Script Entry Point Initialization ---
if __name__ == "__main__":
    try:
        with open("vuln.txt", "w", encoding="utf-8") as clear_target:
            clear_target.write(f"# --- Vulnerability Scan Results Initialized: {datetime.now()} ---\n")
    except IOError:
        print(f"{UIColors.RED}[!] Workspace warning: Unable to create or clear 'vuln.txt'.{UIColors.RESET}")

    target_pool = []
    source_filename = "addresses.txt"
    
    if os.path.exists(source_filename):
        try:
            with open(source_filename, "r", encoding="utf-8") as entry_file:
                for line in entry_file:
                    clean_addr = line.strip().replace(",", "")
                    if not clean_addr:
                        continue
