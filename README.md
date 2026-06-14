# 🔐 API Key Vault

> Encrypted local CLI vault for storing and retrieving API keys by project — no cloud, no leaks.

![Python](https://img.shields.io/badge/Python-3.8+-3776AB?style=flat-square&logo=python&logoColor=white)
![Cryptography](https://img.shields.io/badge/AES--256--GCM-Encrypted-00C853?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-F59E0B?style=flat-square)

---

## Why?

You have 40 projects. Each has an OpenAI key, a Stripe key, and a database URL. You keep them in a .txt file on your Desktop. That file is not encrypted. This fixes that.

API Key Vault stores all your secrets **locally**, **encrypted with AES-256-GCM**, behind a single master password. Nothing is ever sent to the cloud.

---

## Features

- 🔒 **AES-256-GCM encryption** — authenticated encryption, tamper-proof
- 🧂 **PBKDF2 key derivation** — 600,000 iterations, unique salt per vault
- 🗂 **Project-based organization** — group keys by project name
- 📤 **`.env` export** — dump a project's keys to a `.env` file instantly
- 🔄 **Password rotation** — change master password; re-encrypts all secrets
- 💾 **SQLite backend** — single local file, no server needed
- 🎨 **Colorful CLI** — readable, human-friendly terminal output

---

## Installation

```bash
git clone https://github.com/s-shuaib/api-key-vault
cd api-key-vault
pip install cryptography
```

---

## Usage

### 1. Initialize the vault
```bash
python vault.py init
```
Creates `~/.api_vault/` with an encrypted SQLite database.

### 2. Store a key
```bash
python vault.py add myproject OPENAI_API_KEY
# Prompts for master password, then the key value (hidden input)
```

### 3. Retrieve a key
```bash
python vault.py get myproject OPENAI_API_KEY
```

### 4. List all projects
```bash
python vault.py list
```

### 5. List keys in a project
```bash
python vault.py list myproject
```

### 6. Export to `.env` file
```bash
python vault.py export myproject
# Creates myproject.env — add to .gitignore immediately!
```

### 7. Delete a key
```bash
python vault.py delete myproject OPENAI_API_KEY
```

### 8. Delete an entire project
```bash
python vault.py nuke myproject
```

### 9. Change master password
```bash
python vault.py change-password
# Re-encrypts every stored key with the new password
```

---

## Security Model

| Layer | Detail |
|---|---|
| Encryption | AES-256-GCM (authenticated) |
| Key derivation | PBKDF2-HMAC-SHA256, 600k iterations |
| Salt | 32 bytes, random per vault |
| Nonce | 12 bytes, random per value |
| Storage | `~/.api_vault/` with `chmod 600` |
| Master password | Never stored — only a canary ciphertext |

---

## File Structure

```
~/.api_vault/
├── vault.db      # Encrypted SQLite database (chmod 600)
└── meta.json     # Salt + canary for password verification (chmod 600)
```

---

## ⚠️ Important Notes

- **Back up `~/.api_vault/`** — if you lose it, keys are gone forever
- The master password is **never recoverable** — choose wisely
- Exported `.env` files are **plaintext** — treat them like passwords
- Add `*.env` to your global `.gitignore.`

---

## Dependencies

```
cryptography>=41.0.0
```

---

## License

MIT — build on it, ship it, make it yours.
