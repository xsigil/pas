# Technical Specification: `pas` (pastore)

## 1. Objective & Threat Model

`pas` is an anti-forensic, zero-metadata secret manager designed natively for Linux and Wayland. It protects against physical hardware seizure, disk forensics, file system traffic metadata analysis, and memory persistence attacks.

### 1.1 Threat Assumptions

1. **Adversary with Physical / Forensic Block-Level Access**:
   * Inspecting storage blocks reveals no directory structures, credential counts, service names, or access frequencies.
   * File timestamps ($mtime, atime, btime$) are pinned to eliminate temporal correlation with user activity.
   * OpenPGP packet headers leak no cryptographic recipient identities ($KeyID = 0000000000000000$).
2. **Untrusted Runtime Environment**:
   * Clipboard data must not persist indefinitely in display server memory or shared clipboards.
   * Creation of new files must never race against loose permission masks ($umask = 0077$).
   * Unencrypted credential data must never be written to swap, temporary files, or secondary storage.

---

## 2. Storage Architecture: Monolithic Vault

`pas` discards the classic "one file per secret" architecture in favor of a single monolithic, encrypted document.

### 2.1 Storage Layout
```
~/.pastore/
├── .gpg-id         # Mode: 0600, Owner UID read/write only
└── vault.yaml.gpg  # Mode: 0600, Master encrypted payload
```

* **Default Root**: `$HOME/.pastore` (customizable via `PASTORE_DIR`).
* **Vault Filename**: `vault.yaml.gpg`.
* **Zero Structural Leakage**: Virtual paths (e.g. `work/aws/production`) exist exclusively inside the encrypted payload. The physical file system contains zero folders or sub-nodes.

### 2.2 Payload Schema (YAML)

The decrypted payload is a single, structured YAML document:

```yaml
version: 1
updated_at: "2026-10-03T00:00:00Z"
entries:
  - path: "dev/github/personal"
    title: "GitHub Personal"
    account: "octocat"
    url: "https://github.com"
    password: "cryptographic_random_string"
    otp: "otpauth://totp/GitHub:octocat?secret=JBSWY3DPEHPK3PXP"
    created_at: "2026-10-03T00:00:00Z"
    updated_at: "2026-10-03T00:00:00Z"
    comment: |
      Backup emergency recovery codes:
      * 1234-5678-9012
      * 9876-5432-1098
    meta:
      env: "personal"
```

---

## 3. Cryptographic Profile

### 3.1 Encryption Pipeline
* **Engine**: GnuPG (`gpg`)
* **Invocation**:
  ```bash
  gpg --quiet --batch --yes --encrypt --throw-keyids -r <recipient> -o <target_temp_path>
  ```
* **Recipient Privacy (`--throw-keyids`)**: Strips recipient key IDs from public key encrypted packets (RFC 4880 Section 5.1). Key ID is forced to `0000000000000000`.

### 3.2 Decryption Pipeline
* **Target**: Single master read on application invocation.
* **Invocation**:
  ```bash
  gpg --quiet --batch --try-secret-key <recipient> --decrypt <vault_path>
  ```
* Supplying `--try-secret-key` avoids probing unnecessary secret keys in multi-key rings, preventing agent deadlocks and duplicate passphrase dialogs.

### 3.3 Atomic Mutation
All state modifications (`generate`, `mv`, `rm`, `migrate`) use atomic replacement:
1. Serialize modified `Vault` object into valid YAML.
2. Encrypt directly into a temporary file: `.vault-tmp-<nanoseconds>.gpg`.
3. Set temporary file permissions to `0600`.
4. Perform atomic replacement via `os.Rename()`.
5. Apply immediate temporal sanitization to file and directory.

---

## 4. Anti-Forensic Specifications

### 4.1 Temporal Sanitization ($EpochZero$)
Filesystem metadata timestamps are permanently scrubbed:

$$EpochZero = \text{time.Unix}(0, 0).\text{UTC()} \quad (1970\text{-}01\text{-}01\text{ }00:00:00\text{ UTC})$$

After every write operation:
```go
os.Chtimes(vaultPath, EpochZero, EpochZero)
os.Chtimes(storeDir, EpochZero, EpochZero)
```

### 4.2 File Masking ($umask$)
On startup, `init()` enforces a strict process-level file creation mask:
```go
syscall.Umask(0077)
```
No file or directory created by `pas` can ever be opened with group or world permissions.

---

## 5. User Interface & Clipboard Specification

### 5.1 Interactive `fzf` Search
When executed with no arguments, `pas` decrypts the master vault into memory and mounts an interactive `fzf` interface.

* **Format String**:
  ```text
  <Path:34>  │  <Title:24>  │  <Account:24>  │  <URL>
  ```

* **Key Dispatch**:
  | Key Trigger | Selected Attribute | Action |
  | :--- | :--- | :--- |
  | `Enter` (default) | `password` | Wayland clipboard copy |
  | `Ctrl-Y` | `account` | Wayland clipboard copy |
  | `Ctrl-T` | `title` | Wayland clipboard copy |
  | `Ctrl-U` | `url` | Wayland clipboard copy |
  | `Ctrl-O` | `otp` | Wayland clipboard copy |

### 5.2 Wayland Secure Clipboard Lifecycle
Clipboard interactions bypass X11 completely:
1. Spawn `wl-copy -n` and pipe target value through stdin.
2. If `clearSec > 0` (default: 45s), launch an asynchronous cleanup timer.
3. Upon timer expiry, issue `wl-copy --clear` to scrub display server buffers.

---

## 6. Migration Subsystem (`pas migrate`)

The migration engine converts legacy ZX2C4 `pass` file systems into the monolithic structure:
1. Scans source directory recursively for `.gpg` entries, excluding `.git` and `.gpg-id`.
2. Decrypts each record sequentially in-memory.
3. Normalizes CRLF sequences to prevent indentation poisoning.
4. Heuristically maps credentials:
   * First line or `password:` label $\rightarrow$ `password`
   * Second line or `account:` / `user:` label $\rightarrow$ `account`
   * Base filename or `title:` label $\rightarrow$ `title`
   * Domain regex match on filename $\rightarrow$ `url`
   * `otpauth://` or `otp:` label $\rightarrow$ `otp`
   * Remaining unparsed text $\rightarrow$ `comment`
5. Encrypts the compiled `Vault` object into `~/.pastore/vault.yaml.gpg` in a single pass.