<!-- STREAMING_CHUNK:Rendering header and badge section... -->
# pas (pastore)

> **Zero-Metadata, Anti-Forensic Secret Store for Wayland & Linux**  
> *The spiritual, OpSec-hardened successor to standard password stores.*

[![Go Version](https://img.shields.io/badge/go-1.22+-blue.svg)](https://golang.org)
[![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20Wayland-lightgrey.svg)](https://wayland.freedesktop.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Security: Anti--Forensic](https://img.shields.io/badge/OpSec-Temporal%20%26%20Metadata%20Hardened-orange.svg)](#security-architecture)

---

<!-- STREAMING_CHUNK:Documenting the rationale and comparison... -->
## Why `pas`?

Classic tools like `pass` (the standard Unix password manager) encrypt entry *contents*, but leave **vital metadata completely bare**:
- Plaintext filenames reveal sensitive service names (`~/.password-store/Finance/Chase.gpg`, `namethatporn.com.gpg`).
- Plaintext filenames often leak personal email addresses (`user@gmail.com.gpg`).
- Filesystem `mtime` and `atime` timestamps log the exact second you logged into each service, building a forensic chronological profile of your daily life.
- Standard OpenPGP headers expose recipient Key IDs (`-r KEYID`), allowing anyone with disk access to identify who owns the store.

`pas` solves this by treating **all metadata as classified material**, without sacrificing Unix minimalism or interactive speed:

| Feature | Standard `pass` | `pas` |
| :--- | :--- | :--- |
| **Payload Encryption** | GPG symmetric/asymmetric | GPG Asymmetric with `--throw-keyids` (Zero Key ID leakage) |
| **Filenames** | Plaintext (`service/email.gpg`) | **16-char SHA-256 account hash** (`4cbdbf16a427371f.yaml.gpg`) |
| **Filesystem Timestamps** | Leaks real-time activity (`mtime`) | **Fixed to `EpochZero` (`1970-01-01 00:00:00 UTC`)** |
| **Permissions** | System default | Enforced `0700` directories / `0600` files (`umask 0077`) |
| **Data Format** | Fragile multiline text | Structured, human-readable **YAML** inside GPG |
| **Search Experience** | `tree` / linear filename search | **Concurrent in-memory decryption + fuzzy interactive `fzf`** |
| **Clipboard** | `xclip` / `xsel` (X11) | **Native Wayland (`wl-copy`) with auto-clear countdown** |
| **Destruction** | Standard `rm` | **Cryptographic random overwriting (shred) before unlink** |

---

<!-- STREAMING_CHUNK:Documenting architecture and in-memory flow... -->
## Security Architecture

```
            [ Encrypted At Rest on Disk ]
 ├── ~/.pastore/dev/github.com/
 │    └── 4cbdbf16a427371f.yaml.gpg   <-- Access/Mod: 1970-01-01 (EpochZero)
 │                                     <-- Recipient ID: 0000000000000000
 └── ~/.pastore/.gpg-id                <-- Mode: 0600

                       │  Parallel In-Memory Goroutines (CPU x 2)
                       ▼  (Zero plaintext written to disk or swap)

            [ Ephemeral Memory Buffer ]
 ┌───────────────────────────────────────────────────────────────┐
 │ Entry { Title: "GitHub", Account: "zorba", URL: "github.com" }│
 └───────────────────────────────┬───────────────────────────────┘
                                 ▼
                     [ Interactive fzf UI ]
  dev/github.com/4cbdbf1...  │  GitHub  │  zorba  │  github.com
                                 │
     ┌───────────────┬───────────┴───────────┬───────────────┐
   Enter          Ctrl-Y                   Ctrl-U          Ctrl-O
     │               │                       │               │
Password          Account                  URL              OTP
     └───────────────┴───────────┬───────────┴───────────────┘
                                 ▼
                     [ wl-copy (Wayland) ]
                      Auto-clears in 45s
```

---

<!-- STREAMING_CHUNK:Documenting installation and setup... -->
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

<!-- STREAMING_CHUNK:Documenting store initialization and quickstart... -->
## Quickstart

### 1. Initialize Your Store
Set up your store directory (`~/.pastore`) and register your GPG public key:
```bash
mkdir -p ~/.pastore
echo "YOUR_GPG_KEY_FINGERPRINT_OR_EMAIL" > ~/.pastore/.gpg-id
chmod 600 ~/.pastore/.gpg-id
```

### 2. Generate a Hardened Credential
```bash
pas generate -H test-user@zorba.org dev/github.com
```
* Generates a 24-character cryptographic password.
* Automatically hashes the account into `~/.pastore/dev/github.com/<hash>.yaml.gpg`.
* Cleanses the filesystem timestamp to `1970-01-01`.
* Copies the password directly into Wayland clipboard (`wl-copy`), self-destructing in 45 seconds.

### 3. Interactive Search (`fzf`)
Simply invoke `pas` with no arguments:
```bash
pas
```
* **Instant Decryption**: Parallel goroutines decrypt entries into memory without touching disk.
* **4-Column Fuzzy Finder**: Search seamlessly by Directory, Title, Account, or URL.
* **Hotkeys**:
  - `Enter`: Copy **Password**
  - `Ctrl-Y`: Copy **Account / Username**
  - `Ctrl-U`: Copy **URL / Service**
  - `Ctrl-T`: Copy **Title**
  - `Ctrl-O`: Copy **OTP** (if present)

### 4. Move, Rename, and Securely Shred
```bash
# Safely rename/move entry while preserving zero-metadata timestamps:
pas mv dev/github.com/4cbdbf16a427371f personal/github.com/

# Cryptographically overwrite with random noise and delete:
pas rm personal/github.com/4cbdbf16a427371f
```

### 5. Audit & Sanitize
Audit your store to ensure every file and directory strictly adheres to `0700`/`0600` permissions and `EpochZero` timestamps:
```bash
pas audit
```

---

<!-- STREAMING_CHUNK:Documenting legacy migration workflow... -->
## Migrating from ZX2C4 `pass`

Have a store full of plaintext filenames and legacy `.gpg` entries? `pas` includes a stream migration script that:
- Runs **100% in-memory** via GPG pipelines.
- Automatically preserves original filenames as `title` and `url`.
- Parses username/password key-value pairs or multiline formats.
- Anonymizes filenames into 16-character account hashes.

```bash
# Dry run preview (zero changes to disk)
DRY_RUN=1 ./scripts/migrate-legacy.sh

# Perform migration from ~/.password-store to ~/.pastore
./scripts/migrate-legacy.sh
```

---

## License

MIT © [xsigil](https://github.com/xsigil)