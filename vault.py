import os
import sys
import json
import base64
import hashlib
import getpass
import sqlite3
import secrets
import shutil
from pathlib import Path
from datetime import datetime

# ── Cryptography imports ──────────────────────────────────────────────────────
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ── Config ────────────────────────────────────────────────────────────────────
VAULT_DIR  = Path.home() / ".api_vault"
DB_PATH    = VAULT_DIR / "vault.db"
META_PATH  = VAULT_DIR / "meta.json"
ITERATIONS = 600_000   # PBKDF2 iterations (NIST recommended minimum 2023)

# ── ANSI colors ───────────────────────────────────────────────────────────────
R  = "\033[0m"
B  = "\033[1m"
GR = "\033[32m"
YL = "\033[33m"
RD = "\033[31m"
CY = "\033[36m"
DM = "\033[2m"

def banner():
    print(f"""
{CY}{B}╔══════════════════════════════════════╗
║        API KEY VAULT  v1.0           ║
║  Encrypted local storage for secrets ║
╚══════════════════════════════════════╝{R}
""")

def ok(msg):   print(f"  {GR}✓{R}  {msg}")
def err(msg):  print(f"  {RD}✗{R}  {msg}"); sys.exit(1)
def warn(msg): print(f"  {YL}!{R}  {msg}")
def info(msg): print(f"  {CY}→{R}  {msg}")

# ── Key derivation ─────────────────────────────────────────────────────────────
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())

def encrypt(plaintext: str, key: bytes) -> str:
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    ct = aesgcm.encrypt(nonce, plaintext.encode(), None)
    combined = nonce + ct
    return base64.b64encode(combined).decode()

def decrypt(ciphertext_b64: str, key: bytes) -> str:
    data = base64.b64decode(ciphertext_b64)
    nonce, ct = data[:12], data[12:]
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ct, None).decode()

# ── Meta helpers ───────────────────────────────────────────────────────────────
def load_meta() -> dict:
    if not META_PATH.exists():
        err("Vault not initialized. Run: python vault.py init")
    with open(META_PATH) as f:
        return json.load(f)

def save_meta(meta: dict):
    with open(META_PATH, "w") as f:
        json.dump(meta, f, indent=2)

def verify_password(meta: dict) -> bytes:
    password = getpass.getpass(f"  {CY}🔑 Master password:{R} ")
    salt = base64.b64decode(meta["salt"])
    key  = derive_key(password, salt)
    # Verify by decrypting the canary
    try:
        result = decrypt(meta["canary"], key)
        if result != "vault-canary-ok":
            err("Wrong password.")
    except Exception:
        err("Wrong password.")
    return key
