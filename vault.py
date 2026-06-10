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

# ── DB helpers ─────────────────────────────────────────────────────────────────
def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("""
        CREATE TABLE IF NOT EXISTS keys (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            project   TEXT NOT NULL,
            key_name  TEXT NOT NULL,
            value_enc TEXT NOT NULL,
            created   TEXT NOT NULL,
            updated   TEXT NOT NULL,
            UNIQUE(project, key_name)
        )
    """)
    conn.commit()
    return conn

def now_str():
    return datetime.now().strftime("%Y-%m-%d %H:%M")

# ── Commands ───────────────────────────────────────────────────────────────────

def cmd_init():
    banner()
    if VAULT_DIR.exists() and META_PATH.exists():
        warn("Vault already exists.")
        confirm = input(f"  {YL}Re-initialize? This will ERASE all data. (yes/no):{R} ").strip()
        if confirm.lower() != "yes":
            info("Aborted.")
            return
        shutil.rmtree(VAULT_DIR)

    VAULT_DIR.mkdir(mode=0o700, exist_ok=True)

    print(f"  {CY}Choose a strong master password (it will never be stored).{R}")
    while True:
        pw1 = getpass.getpass(f"  {CY}New master password:{R} ")
        pw2 = getpass.getpass(f"  {CY}Confirm password:{R}    ")
        if pw1 != pw2:
            warn("Passwords don't match. Try again.")
            continue
        if len(pw1) < 8:
            warn("Password must be at least 8 characters.")
            continue
        break

    salt = secrets.token_bytes(32)
    key  = derive_key(pw1, salt)
    canary = encrypt("vault-canary-ok", key)

    meta = {
        "version":    1,
        "salt":       base64.b64encode(salt).decode(),
        "canary":     canary,
        "iterations": ITERATIONS,
        "created":    now_str(),
    }
    save_meta(meta)
    # Create DB
    conn = get_conn(); conn.close()
    # Lock down permissions
    DB_PATH.chmod(0o600)
    META_PATH.chmod(0o600)

    ok("Vault initialized successfully!")
    info(f"Vault location: {VAULT_DIR}")
    print()


def cmd_add(project: str, key_name: str):
    banner()
    meta = load_meta()
    key  = verify_password(meta)
    value = getpass.getpass(f"  {CY}Value for {B}{project}/{key_name}{R}{CY}:{R} ")
    if not value.strip():
        err("Value cannot be empty.")

    enc = encrypt(value, key)
    conn = get_conn()
    ts = now_str()
    conn.execute("""
        INSERT INTO keys (project, key_name, value_enc, created, updated)
        VALUES (?,?,?,?,?)
        ON CONFLICT(project, key_name) DO UPDATE
          SET value_enc=excluded.value_enc, updated=excluded.updated
    """, (project, key_name, enc, ts, ts))
    conn.commit(); conn.close()
    ok(f"Saved {CY}{project}/{key_name}{R}")
    print()


def cmd_get(project: str, key_name: str):
    banner()
    meta = load_meta()
    key  = verify_password(meta)
    conn = get_conn()
    row  = conn.execute(
        "SELECT value_enc, updated FROM keys WHERE project=? AND key_name=?",
        (project, key_name)
    ).fetchone()
    conn.close()
    if not row:
        err(f"Key '{project}/{key_name}' not found.")

    value = decrypt(row["value_enc"], key)
    print(f"\n  {B}Project:{R}  {CY}{project}{R}")
    print(f"  {B}Key:{R}      {CY}{key_name}{R}")
    print(f"  {B}Value:{R}    {GR}{value}{R}")
    print(f"  {B}Updated:{R}  {DM}{row['updated']}{R}\n")


def cmd_list(project: str = None):
    banner()
    meta = load_meta()
    # No password needed — just shows project/key names (not values)
    conn = get_conn()
    if project:
        rows = conn.execute(
            "SELECT key_name, updated FROM keys WHERE project=? ORDER BY key_name",
            (project,)
        ).fetchall()
        conn.close()
        if not rows:
            warn(f"No keys found for project '{project}'.")
            return
        print(f"  {B}{CY}{project}{R}\n")
        for r in rows:
            print(f"    {GR}•{R} {r['key_name']:<30} {DM}{r['updated']}{R}")
    else:
        rows = conn.execute(
            "SELECT project, COUNT(*) as cnt, MAX(updated) as latest FROM keys GROUP BY project ORDER BY project"
        ).fetchall()
        conn.close()
        if not rows:
            warn("Vault is empty. Add keys with: python vault.py add <project> <key_name>")
            return
        print(f"  {'PROJECT':<24} {'KEYS':>5}  {'LAST UPDATED'}\n  {'─'*55}")
        for r in rows:
            print(f"  {CY}{r['project']:<24}{R} {r['cnt']:>5}  {DM}{r['latest']}{R}")
