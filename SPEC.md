<!-- STREAMING_CHUNK:Updating architectural specification... -->
# Technical Specification: `pas` (pastore)

## 1. Objective & Threat Model

`pas` is a modern, anti-forensic secret manager built natively for Linux/Wayland environments. It addresses physical asset seizure, traffic metadata analysis, and timeline reconstruction forensics.

### Threat Assumptions
1. **Adversary with Forensic Filesystem Access**:
   - Inspecting directory trees and filenames reveals nothing about enrolled institutions, banks, or identities.
   - Filesystem metadata (`mtime`, `atime`, `btime`) contains no chronological trace of access or modification patterns.
   - Raw OpenPGP headers on storage do not expose target recipient identities.
2. **Untrusted Shared Runtime**:
   - Ephemeral clipboard contents must not linger in display memory or clipboard buffers.
   - File creation must never race against wide permissions (process-wide `umask 0077`).
   - Plaintext credentials must never touch disks or swap.

---

<!-- STREAMING_CHUNK:Documenting payload and hashing mechanics... -->
## 2. Core Formats & Identifiers

### 2.1 File Path Resolution
* **Directory Root**: Default `$HOME/.pastore` (customizable via `PASTORE_DIR`).
* **Leaf Node Identifier**:
  $$\text{HashName} = \text{SHA256}(\text{account})[0:16] + \text{".yaml.gpg"}$$
  If no explicit account identifier exists, the base title is used as fallback input to SHA-256.

### 2.2 Encrypted Payload Format (YAML inside GPG)
```yaml
password: "cryptographic_secret_here"
title: "Original Service Name"
account: "user@example.com"
url: "https://service.example.com"
otp: "totp_secret_or_otpauth_uri"
created_at: "2026-10-03T00:00:00Z"
updated_at: "2026-10-03T00:00:00Z"
comment: |
  Optional notes or backup recovery codes
```

---

<!-- STREAMING_CHUNK:Documenting cryptographic parameters and execution flow... -->
## 3. Cryptographic Operations

### 3.1 Encryption Profile
* Engine: GnuPG (`gpg`)
* Parameters:
  ```bash
  gpg --quiet --batch --yes --encrypt --throw-keyids -r <recipient> -o <target_path>
  ```
* `--throw-keyids` forces anonymous recipient headers (`ID 0000000000000000`), defeating key-fingerprinting attacks.

### 3.2 Decryption & Parallel Indexing
* Goroutine worker pool scaled dynamically to `runtime.NumCPU() * 2`.
* Non-blocking buffered channels pipe decrypted headers straight into the `fzf` UI indexer without writing any temporary bytes to disk.

### 3.3 Secure Erasure (`pas rm`)
* Overwrite target file with pseudo-random byte stream matching exact size.
* Issue `fsync()` system call.
* Unlink node via `os.Remove()`.

---

## 4. UI / Interactive Search Specification

`pas` launches an interactive `fzf` terminal UI when executed without positional arguments.

### Format String
```text
<RelPath:30>  │  <Title:22>  │  <Account:24>  │  <URL>
```

### Action Dispatch Table
| Key Trigger | Extracted YAML Property | Target Destination |
| :--- | :--- | :--- |
| `Enter` (default) | `password` | `wl-copy -n` (auto-clear: 45s) |
| `Ctrl-Y` | `account` | `wl-copy -n` (auto-clear: 45s) |
| `Ctrl-U` | `url` | `wl-copy -n` (auto-clear: 45s) |
| `Ctrl-T` | `title` | `wl-copy -n` (auto-clear: 45s) |
| `Ctrl-O` | `otp` | `wl-copy -n` (auto-clear: 45s) |

---

## 5. Temporal Sanitization Specification
Every file modification, creation, or directory move operation triggers an explicit `os.Chtimes(path, EpochZero, EpochZero)` where:
$$\text{EpochZero} = \text{time.Unix}(0, 0).\text{UTC()} \quad (1970\text{-}01\text{-}01\text{ }00:00:00\text{ UTC})$$
Directory ancestry trees are sanitized recursively up to the repository root.