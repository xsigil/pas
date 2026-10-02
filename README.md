# pas (pastore)

> **Zero-Metadata, Anti-Forensic Secret Fortress for Wayland & Linux**  
> *A hardened, monolithic encrypted secret vault eliminating temporal, structural, and recipient traces.*

[![Go Version](https://img.shields.io/badge/go-1.22+-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Wayland-lightgrey.svg)](https://wayland.freedesktop.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security: Monolithic Vault](https://img.shields.io/badge/Architecture-Monolithic%20Encrypted%20Vault-orange.svg)](#threat-model--monolithic-architecture)

---

## Why `pas`?

Classic secret managers like standard Unix `pass` (ZX2C4) encrypt the *payload* of individual entries, but leave critical system metadata naked to forensic extraction:

- **Directory & Filename Leaks**: Disk trees directly advertise every bank, institutional service, and personal email address you use (`~/.password-store/Finance/Chase/user@example.com.gpg`).
- **Activity Timelines**: Filesystem `mtime` and `atime` timestamps log access moments down to the second, allowing investigators to construct your daily schedule.
- **Entry Counts & Sizing**: The number of `.gpg` files on disk discloses exactly how many secrets you hold; file sizes hint at notes or recovery codes.
- **OpenPGP Key ID Exposure**: Normal GPG headers store recipient Key IDs, tying encrypted records directly to public cryptographic identities.
- **Agent Flooding**: Decrypting hundreds of isolated files creates IPC race conditions and repeated pinentry passphrase prompts.

`pas` eliminates these attack vectors with a **Monolithic Encrypted Vault** architecture. The entire repository is aggregated into a single, anonymous encrypted file:

| Attack Vector / Metric | Standard `pass` | Multi-file Tools | `pas` (Monolithic Vault) |
| :--- | :--- | :--- | :--- |
| **Filesystem Tree** | Exposed on disk | Hash-anonymized | **Zero directory tree on disk** |
| **File Count** | Number of secrets exposed | Number of secrets exposed | **Exactly 1 master vault file** |
| **Individual Entry Size** | Leaked per secret | Leaked per secret | **Fully aggregated & hidden** |
| **Access Timestamps** | Real-time forensic log | Partially masked | **Fixed to `1970-01-01` (EpochZero)** |
| **Recipient Key IDs** | Plaintext Key ID in headers | Often exposed | **`--throw-keyids` (Zero key leakage)** |
| **Passphrase Entry** | Repeated prompts or caching | Agent race conditions | **Single unlock on load** |
| **Search Performance** | Linear file reads | Parallel GPG spawns | **Single in-memory decrypt + instant `fzf`** |
| **Display Protocol** | X11 (`xclip` clipboard snoop) | Mixed | **Native Wayland (`wl-copy`) with auto-clear** |

---

## Threat Model & Monolithic Architecture

```
                  [ Physical Storage at Rest ]
                  ~/.pastore/
                  ├── .gpg-id         (Mode: 0600)
                  └── vault.yaml.gpg  (Mode: 0600, mtime: 1970-01-01 00:00:00 UTC)
                                      (Recipient ID: 0000000000000000)

                                       │
                                       │ 1. Single GPG Decrypt (1 Master Passphrase Prompt)
                                       ▼
                       [ Ephemeral Process Memory ]
        ┌─────────────────────────────────────────────────────────────┐
        │ Vault { Version: 1, Entries: [ ...460+ Credential Records ] }│
        └──────────────────────────────┬──────────────────────────────┘
                                       │
                                       ▼
                             [ Interactive fzf UI ]
┌──────────────────────────────────────────────────────────────────────────────────┐
│ _network/home/rental/api.heroku.com  │  Heroku API  │  user@example.com  │  ...  │
└──────────────────────────────────────┬───────────────────────────────────────────┘
                                       │
               ┌───────────┬───────────┼───────────┬───────────┐
             Enter       Ctrl-Y      Ctrl-T      Ctrl-U      Ctrl-O
               │           │           │           │           │
            Password    Account      Title        URL         OTP
               └───────────┴───────────┬───────────┴───────────┘
                                       ▼
                         [ Wayland Secure Clipboard ]
                         `wl-copy -n` (Auto-clears in 45s)
```

1. **Physical Asset Seizure**:
   An adversary capturing the raw storage drive finds a solitary file: `vault.yaml.gpg`. They cannot deduce how many credentials exist, what hierarchies or domains are stored, or which key fingerprint was used to encrypt it.
2. **Temporal Neutralization**:
   Every write operation creates an atomic temporary file, replaces the vault, and resets directory and file timestamps to `1970-01-01 00:00:00 UTC` (`EpochZero`).
3. **Zero Plaintext Disk Spill**:
   Edits, imports, moves, and deletions occur in memory. Plaintext YAML never touches disk, temp directories, or unencrypted swap.

---

## Installation

### Prerequisites (Arch Linux / Wayland)
```bash
sudo pacman -S go gnupg fzf wl-clipboard
```

### Build & Install
```bash
git clone https://github.com/xsigil/pas.git
cd pas
make
sudo make install
```

---

## Quickstart

### 1. Initialize Recipient Key
Create your secure vault directory and register your GPG public key ID:
```bash
mkdir -p ~/.pastore
chmod 700 ~/.pastore
echo "YOUR_GPG_KEY_FINGERPRINT_OR_ID" > ~/.pastore/.gpg-id
chmod 600 ~/.pastore/.gpg-id
```

### 2. Generate a Hardened Credential
```bash
pas generate -a user@example.com -t "GitHub Personal" -u "github.com" dev/github/personal
```
- Creates a 24-character cryptographic password.
- Atomically encrypts the record into `~/.pastore/vault.yaml.gpg`.
- Copies the password to Wayland clipboard with a 45-second auto-clear countdown.
- Normalizes filesystem timestamps to `1970-01-01`.

### 3. Interactive Search (`fzf`)
Execute `pas` without arguments:
```bash
pas
```
- **Instant Decryption**: The master vault decrypts once in memory.
- **4-Column Fuzzy Finder**: Search across Virtual Path, Title, Account, or URL.
- **Actions**:
  - `Enter`: Copy **Password**
  - `Ctrl-Y`: Copy **Account / Username**
  - `Ctrl-T`: Copy **Title / Friendly Name**
  - `Ctrl-U`: Copy **Service URL**
  - `Ctrl-O`: Copy **OTP Secret**

---

## CLI Reference

### Direct Retrieval
```bash
# Copy password for specific path
pas dev/github/personal

# Copy username/account
pas dev/github/personal account

# Print password directly to stdout
pas -p dev/github/personal

# Print entire YAML entry block
pas -p dev/github/personal ""

# Custom clipboard auto-clear duration (e.g. 10 seconds)
pas -clear 10 dev/github/personal
```

### Structural Reorganization (`mv`)
Reorganize entries or entire directory hierarchies without leaving filesystem traces:
```bash
# Move a single entry
pas mv dev/github/personal work/github/personal

# Move an entire virtual directory tree
pas mv _network/home/ infra/home/
```

### Deletion (`rm`)
```bash
# Remove a single entry
pas rm work/github/personal

# Recursively remove an entire virtual path tree
pas rm -r infra/home
```

### Auditing & Sanitization (`audit`)
Ensure file modes and timestamps strictly conform to the security baseline:
```bash
pas audit
```

### Vault Export (`export`)
Dump the decrypted YAML vault to stdout (ideal for encrypted off-site backups or piping):
```bash
pas export | gpg --symmetric -o backup-vault.yaml.gpg
```

---

## Migrating from Legacy `pass` (ZX2C4)

`pas` provides a native migration engine that sequentially parses existing multi-file stores and compiles them into a single monolithic vault:

```bash
# Migrate from default ~/.password-store to ~/.pastore
pas migrate

# Migrate from a custom directory
pas migrate -from /path/to/legacy-store
```

The migration engine:
- Reads all `.gpg` files sequentially without agent concurrency races.
- Automatically preserves original file paths as the virtual `path`.
- Detects filenames as friendly `title` and extracts URLs when domains are present.
- Extracts `password:`, `account:`, `url:`, and `otp:` labels, falling back to positional lines.
- Normalizes CRLF line endings to prevent YAML parse failures.
- Atomically writes and encrypts `vault.yaml.gpg` with `--throw-keyids`.

---

## License

MIT © [xsigil](https://github.com/xsigil)