import requests 
import time 
from ecdsa.numbertheory import inverse_mod 
from hashlib import sha256 
import os 
from collections import defaultdict 
from datetime import datetime 
import signal 
import sys 
import math 
import json 
from ecdsa import SECP256k1, SigningKey, VerifyingKey 
import binascii 
import struct 
import io 
from Crypto.Hash import RIPEMD160  # Required for hash160()

class Colors: 
    RESET = '\033[0m' 
    BLACK = '\033[30m' 
    RED = '\033[31m' 
    GREEN = '\033[32m' 
    YELLOW = '\033[33m' 
    BLUE = '\033[34m' 
    MAGENTA = '\033[35m' 
    CYAN = '\033[36m' 
    WHITE = '\033[37m' 
    ORANGE = '\033[93m' 
    BRIGHT_BLACK = '\033[90m' 
    BRIGHT_RED = '\033[91m' 
    BRIGHT_GREEN = '\033[92m' 
    BRIGHT_YELLOW = '\033[93m' 
    BRIGHT_BLUE = '\033[94m' 
    BRIGHT_MAGENTA = '\033[95m' 
    BRIGHT_CYAN = '\033[96m' 
    BRIGHT_WHITE = '\033[97m' 
    BRIGHT_ORANGE = '\033[93m' 
    BG_BLACK = '\033[40m' 
    BG_RED = '\033[41m' 
    BG_GREEN = '\033[42m' 
    BG_YELLOW = '\033[43m' 
    BG_BLUE = '\033[44m' 
    BG_MAGENTA = '\033[45m' 
    BG_CYAN = '\033[46m' 
    BG_WHITE = '\033[47m' 
    BG_ORANGE = '\033[93m' 
    BOLD = '\033[1m' 
    UNDERLINE = '\033[4m' 
    INVERT = '\033[7m' 

# --- API Configuration (blockchain.info completely removed) --- 
API_ORDER_TOTAL_TX = [ 
    "mempool", 
    "blockstream", 
    "sochain", 
    "btc_com" 
] 

API_ORDER_RAW_HEX_FALLBACK = [ 
    ("mempool", "/tx/{txid}/hex"), 
    ("blockstream", "/tx/{txid}/hex"), 
    ("blockstream", "/tx/{txid}"), 
    ("sochain", "/get_tx/BTC/{txid}"), 
    ("btc_com", "/tx/{txid}") 
] 

API_CONFIGS = { 
    "mempool": { 
        "base_url": "https://mempool.space", 
        "total_tx_endpoint": "/address/{address}", 
        "tx_list_endpoint": "/address/{address}/txs", 
        "raw_tx_endpoint_hex": "/tx/{txid}/hex", 
        "parser": { 
            "total_tx": lambda data: data.get('chain_stats', {}).get('tx_count', 0), 
            "transactions_from_list": lambda data: [tx.get('txid') for tx in data if tx.get('txid')], 
            "get_raw_hex_from_plain_response": lambda response_text: response_text 
        } 
    }, 
    "blockstream": { 
        "base_url": "https://blockstream.info", 
        "total_tx_endpoint": "/address/{address}", 
        "tx_list_endpoint": "/address/{address}/txs", 
        "raw_tx_endpoint_hex": "/tx/{txid}/hex", 
        "raw_tx_endpoint_json": "/tx/{txid}", 
        "parser": { 
            "total_tx": lambda data: data.get('chain_stats', {}).get('tx_count', 0), 
            "transactions_from_list": lambda data: [tx.get('txid') for tx in data if tx.get('txid')], 
            "get_raw_hex_from_plain_response": lambda response_text: response_text, 
            "get_raw_hex_from_json_response": lambda data: data.get('hex', None) 
        } 
    }, 
    "sochain": { 
        "base_url": "https://sochain.com", 
        "total_tx_endpoint": "/address/BTC/{address}", 
        "tx_list_endpoint": "/address/BTC/{address}", 
        "raw_tx_endpoint_json": "/get_tx/BTC/{txid}", 
        "parser": { 
            "total_tx": lambda data: data.get('data', {}).get('txs', []).__len__(), 
            "transactions_from_list": lambda data: [tx.get('txid') for tx in data.get('data', {}).get('txs', []) if tx.get('txid')], 
            "get_raw_hex_from_json_response": lambda data: data.get('data', {}).get('tx_hex', None) 
        } 
    }, 
    "btc_com": { 
        "base_url": "https://btc.com", 
        "total_tx_endpoint": "/address/{address}", 
        "tx_list_endpoint": "/address/{address}/tx?offset={offset}&limit={limit}", 
        "raw_tx_endpoint_json": "/tx/{txid}", 
        "parser": { 
            "total_tx": lambda data: data.get('data', {}).get('total_tx', 0), 
            "transactions_from_list": lambda data: [tx.get('hash') for tx in data.get('data', {}).get('list', []) if tx.get('hash')], 
            "get_raw_hex_from_json_response": lambda data: data.get('data', {}).get('hex', None) 
        } 
    } 
} 

# Global variables for reporting 
TOTAL_ADDRESSES = 0 
SCANNED_ADDRESSES = 0 
VULNERABLE_ADDRESSES = 0 
VULN_COUNTS = defaultdict(int) 
CURRENT_ADDRESS = "" 
SCANNED_ADDRESS_LIST = [] 
MAX_DISPLAYED_ADDRESSES = 10 
EXIT_FLAG = False 
REPORTS = [] 
MAX_TRANSACTIONS = 0 
GLOBAL_MAX_SMALL_K_ATTEMPT = 0 

# Configurable delay between API calls (in seconds) 
SCAN_DELAY_SECONDS = 0.5 

# Constants for SECP256k1 
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F 
N = SECP256k1.order 
G = SECP256k1.generator 

S_MAX_HALF = N // 2 

_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" 

# Bitcoin Script Opcodes (Relevant for parsing) 
OP_DUP = 0x76 
OP_HASH160 = 0xA9 
OP_EQUALVERIFY = 0x88 
OP_CHECKSIG = 0xAC 
OP_EQUAL = 0x87 
OP_CHECKMULTISIG = 0xAE 
OP_0 = 0x00 
OP_1 = 0x51 
OP_2 = 0x52 
OP_3 = 0x53 
OP_4 = 0x54 
OP_5 = 0x55 
OP_6 = 0x56 
OP_7 = 0x57 
OP_8 = 0x58 
OP_9 = 0x59 
OP_10 = 0x5a 
OP_11 = 0x5b 
OP_12 = 0x5c 
OP_13 = 0x5d 
OP_14 = 0x5e 
OP_15 = 0x5f 
OP_16 = 0x60 

# Map OP_N to integer N 
OP_N_MAPPING = { 
    OP_0: 0, OP_1: 1, OP_2: 2, OP_3: 3, OP_4: 4, OP_5: 5, OP_6: 6, OP_7: 7, OP_8: 8, 
    OP_9: 9, OP_10: 10, OP_11: 11, OP_12: 12, OP_13: 13, OP_14: 14, OP_15: 15, OP_16: 16 
} 

# Nonce Bias Threshold 
NONCE_BIAS_THRESHOLD = 2 

# Cache for fetched raw transaction hexes 
TX_RAW_HEX_CACHE = {} 

# --- Utility Functions --- 

def signal_handler(sig, frame): 
    global EXIT_FLAG 
    print(f"\n{Colors.YELLOW}Signal {sig} received. Preparing to stop scanning.{Colors.RESET}") 
    EXIT_FLAG = True 

signal.signal(signal.SIGINT, signal_handler) 
signal.signal(signal.SIGTERM, signal_handler) 

def hex_to_int(h): 
    return int(h, 16) 

def int_to_hex(i): 
    return hex(i) 

def hash160(public_key_bytes): 
    ripemd160 = RIPEMD160.new() 
    ripemd160.update(sha256(public_key_bytes).digest()) 
    return ripemd160.digest() 

def encode_base58(v): 
    base58_string = b"" 
    x = int.from_bytes(v, 'big') 
    while x > 0: 
        x, mod = divmod(x, 58) 
        base58_string = _BASE58_ALPHABET[mod:mod+1] + base58_string 

    for byte in v: 
        if byte == 0x00: 
            base58_string = b"1" + base58_string 
        else: 
            break 
    return base58_string.decode('utf-8') 

def point_to_pubkey_bytes(point, compressed=True): 
    if compressed: 
        prefix = b'\x02' if point.y() % 2 == 0 else b'\x03' 
        return prefix + point.x().to_bytes(32, byteorder='big') 
    else: 
        return b'\x04' + point.x().to_bytes(32, byteorder='big') + point.y().to_bytes(32, byteorder='big') 

def public_key_to_address(public_key_hex, is_compressed=True, script_type='P2PKH'): 
    try: 
        public_key_bytes = binascii.unhexlify(public_key_hex) 
         
        if script_type == 'P2PKH': 
            if is_compressed: 
                vh160 = b'\x00' + hash160(public_key_bytes) 
            else: 
                vh160 = b'\x00' + hash160(public_key_bytes) 
             
            checksum = sha256(sha256(vh160).digest()).digest()[:4] 
            address = encode_base58(vh160 + checksum) 
            return address 
        elif script_type == 'P2WPKH': 
            return "P2WPKH_Address_Requires_Bech32_Encoding" 
        elif script_type == 'P2SH-P2WPKH': 
            redeem_script = b'\x00\x14' + hash160(public_key_bytes) 
            script_hash = hash160(redeem_script) 
            vh160 = b'\x05' + script_hash 
            checksum = sha256(sha256(vh160).digest()).digest()[:4] 
            address = encode_base58(vh160 + checksum) 
            return address 
        else: 
            return "Unsupported_Script_Type" 
    except Exception as e: 
        return "Invalid_Pubkey_Address_Conversion_Error" 

def display_stats(): 
    os.system('cls' if os.name == 'nt' else 'clear') 
    print(f"{Colors.BRIGHT_CYAN}{'='*80}{Colors.RESET}") 
    print(f"{Colors.BRIGHT_BLUE}🔍 Signature Scanner for Bitcoin Vulnerability{Colors.RESET}") 
    print(f"{Colors.BRIGHT_BLACK}📅 Scan Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Colors.RESET}") 
    print(f"{Colors.BRIGHT_BLUE}🔧 SecAnalysts @2025 | Ctrl+C to stop scan{Colors.RESET}") 
    print(f"{Colors.BRIGHT_BLUE}💰 DONATE BITCOIN :1sAXERLyPhg4Fg4rkhuRQfm9eek2NJo6V{Colors.RESET}") 
    print(f"{Colors.BRIGHT_CYAN}{'='*80}{Colors.RESET}") 
    print(f"{Colors.BRIGHT_WHITE}📊 Progress Statistics:{Colors.RESET}") 
    print(f"  {Colors.WHITE}• Total Addresses:{Colors.RESET} {Colors.YELLOW}{TOTAL_ADDRESSES}{Colors.RESET}") 
    print(f"  {Colors.WHITE}• Remaining Addresses:{Colors.RESET} {Colors.YELLOW}{TOTAL_ADDRESSES - SCANNED_ADDRESSES}{Colors.RESET}") 
    print(f"  {Colors.WHITE}• Scanned Addresses:{Colors.RESET} {Colors.CYAN}{SCANNED_ADDRESSES}{Colors.RESET}") 
    percentage = (VULNERABLE_ADDRESSES/SCANNED_ADDRESSES*100) if SCANNED_ADDRESSES > 0 else 0 
    vuln_color = Colors.GREEN if percentage == 0 else Colors.YELLOW if percentage < 10 else Colors.RED 
    print(f"  {Colors.WHITE}• Vulnerable Addresses:{Colors.RESET} {vuln_color}{VULNERABLE_ADDRESSES} ({percentage:.1f}%){Colors.RESET}") 
    print(f"{Colors.BRIGHT_CYAN}{'='*80}{Colors.RESET}") 

    # Perfectly aligned vulnerability table 
    print(f"\n{Colors.BRIGHT_WHITE}🚨 Vulnerability Summary:{Colors.RESET}") 
     
    # Define column widths and styles 
    SEV_WIDTH = 14 
    VULN_WIDTH = 38 
    COUNT_WIDTH = 8 
    BORDER = Colors.BRIGHT_CYAN 
    HEADER = Colors.BRIGHT_WHITE 
    RESET = Colors.RESET 
     
    # Table header 
    print(f"{BORDER}╔{'═'*SEV_WIDTH}╦{'═'*VULN_WIDTH}╦{'═'*COUNT_WIDTH}╗{RESET}") 
    print(f"{BORDER}║{HEADER}{'Severity'.center(SEV_WIDTH)}{BORDER}║{HEADER}{'Vulnerability'.center(VULN_WIDTH)}{BORDER}║{HEADER}{'Count'.center(COUNT_WIDTH)}{BORDER}║{RESET}") 
    print(f"{BORDER}╠{'═'*SEV_WIDTH}╬{'═'*VULN_WIDTH}╬{'═'*COUNT_WIDTH}╣{RESET}") 

    # Helper function to print table rows 
