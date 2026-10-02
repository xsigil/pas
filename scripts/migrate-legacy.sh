#!/usr/bin/env bash
# STREAMING_CHUNK:Configuring safety options and environment defaults...
set -euo pipefail

# pas Legacy Store Migration Tool
# Migrates ZX2C4 pass stores to zero-metadata .yaml.gpg format
# Features:
#   - In-memory pipe (zero plaintext on disk)
#   - Title extraction from original filename or payload
#   - Intelligent multi-format parser (key-value, positional, otpauth)
#   - Anti-forensic 16-char SHA-256 account hashing
#   - Temporal obfuscation (EpochZero: 1970-01-01 00:00:00 UTC)
#   - Strict permissions (0700 dir / 0600 file)

SRC_DIR="${SRC_DIR:-$HOME/.password-store}"
DST_DIR="${DST_DIR:-$HOME/.pastore}"
DRY_RUN="${DRY_RUN:-0}"
SHRED_OLD="${SHRED_OLD:-0}"

# STREAMING_CHUNK:Validating dependencies and directory structure...
echo "==> Verifying environment and cryptographic dependencies..."
for cmd in gpg gawk sha256sum touch chmod mkdir; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "Error: Required command '$cmd' is not installed." >&2
        exit 1
    fi
done

if [ ! -d "$SRC_DIR" ]; then
    echo "Error: Source store '$SRC_DIR' not found." >&2
    exit 1
fi

mkdir -p "$DST_DIR"
chmod 700 "$DST_DIR"
umask 077

# STREAMING_CHUNK:Resolving GPG recipient keys...
if [ -f "$DST_DIR/.gpg-id" ]; then
    RECIPIENTS_FILE="$DST_DIR/.gpg-id"
elif [ -f "$SRC_DIR/.gpg-id" ]; then
    cp "$SRC_DIR/.gpg-id" "$DST_DIR/.gpg-id"
    chmod 600 "$DST_DIR/.gpg-id"
    RECIPIENTS_FILE="$DST_DIR/.gpg-id"
else
    echo "Error: No .gpg-id found in either source or destination store." >&2
    exit 1
fi

GPG_RECIPIENT_ARGS=()
while IFS= read -r recipient || [ -n "$recipient" ]; do
    trimmed=$(echo "$recipient" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    if [[ -n "$trimmed" && ! "$trimmed" =~ ^# ]]; then
        GPG_RECIPIENT_ARGS+=("-r" "$trimmed")
    fi
done < "$RECIPIENTS_FILE"

if [ ${#GPG_RECIPIENT_ARGS[@]} -eq 0 ]; then
    echo "Error: No valid recipients found in $RECIPIENTS_FILE" >&2
    exit 1
fi

# STREAMING_CHUNK:Initializing migration counters and scanning files...
echo "==> Source Store:      $SRC_DIR"
echo "==> Destination Store: $DST_DIR"
echo "==> Dry-run mode:      $DRY_RUN"
echo "==> Shred old files:   $SHRED_OLD"
echo "--------------------------------------------------------"

total_count=0
migrated_count=0
skipped_count=0

# STREAMING_CHUNK:Processing legacy entries in an in-memory loop...
while IFS= read -r -d '' src_file; do
    rel_path="${src_file#$SRC_DIR/}"

    # Skip git internal metadata, .gpg-id, and already migrated .yaml.gpg files
    if [[ "$rel_path" =~ ^\.git/ ]] || [[ "$rel_path" == ".gpg-id" ]] || [[ "$rel_path" == *".yaml.gpg" ]]; then
        continue
    fi

    total_count=$((total_count + 1))
    rel_dir=$(dirname "$rel_path")
    base_name=$(basename "$rel_path" .gpg)

    # Decrypt in-memory without disk leakage
    if ! decrypted=$(gpg --quiet --batch --decrypt "$src_file" 2>/dev/null); then
        echo "[SKIP] Decrypt failed: $rel_path" >&2
        skipped_count=$((skipped_count + 1))
        continue
    fi

    now_utc=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    # STREAMING_CHUNK:Parsing entry attributes and formatting YAML via gawk...
    parsed_output=$(echo "$decrypted" | gawk -v now="$now_utc" -v orig_title="$base_name" '
    function trim(str) {
        sub(/^[[:space:]]+/, "", str)
        sub(/[[:space:]]+$/, "", str)
        return str
    }
    function yaml_quote(str) {
        gsub(/\\/, "\\\\", str)
        gsub(/"/, "\\\"", str)
        return "\"" str "\""
    }

    BEGIN {
        total = 0
        pass = ""
        title = ""
        acc = ""
        url = ""
        otp = ""
    }

    {
        total++
        lines[total] = $0
        used[total] = 0
    }

    END {
        # Pass 1: Scan for explicit key-value labels
        for (i = 1; i <= total; i++) {
            line = lines[i]
            if (match(line, /^[[:space:]]*(password|pass)[[:space:]]*:[[:space:]]*(.*)$/, m)) {
                if (pass == "") { pass = trim(m[2]); used[i] = 1; }
            } else if (match(line, /^[[:space:]]*(title|name|service_name)[[:space:]]*:[[:space:]]*(.*)$/, m)) {
                if (title == "") { title = trim(m[2]); used[i] = 1; }
            } else if (match(line, /^[[:space:]]*(account|user|username|email|login)[[:space:]]*:[[:space:]]*(.*)$/, m)) {
                if (acc == "") { acc = trim(m[2]); used[i] = 1; }
            } else if (match(line, /^[[:space:]]*(url|uri|link|service)[[:space:]]*:[[:space:]]*(.*)$/, m)) {
                if (url == "") { url = trim(m[2]); used[i] = 1; }
            } else if (match(line, /^[[:space:]]*(otp|totp)[[:space:]]*:[[:space:]]*(.*)$/, m)) {
                if (otp == "") { otp = trim(m[2]); used[i] = 1; }
            } else if (match(line, /^[[:space:]]*otpauth:\/\//)) {
                if (otp == "") { otp = trim(line); used[i] = 1; }
            }
        }

        # Pass 2: Positional fallback for unlabeled entries
        if (pass == "") {
            for (i = 1; i <= total; i++) {
                if (!used[i] && trim(lines[i]) != "") {
                    pass = lines[i]
                    used[i] = 1
                    break
                }
            }
        }

        if (acc == "") {
            for (i = 1; i <= total; i++) {
                t = trim(lines[i])
                if (!used[i] && t != "" && t !~ /^---/) {
                    acc = t
                    used[i] = 1
                    break
                }
            }
        }

        # Pass 3: Preserve original filename as title
        if (title == "") {
            title = orig_title
        }

        # Pass 4: If url is empty and title looks like a domain/URL, use it
        if (url == "") {
            if (orig_title ~ /\.(com|org|net|io|jp|local|me|ltd|la|dev|info|biz|co|app)/ || orig_title ~ /^https?:\/\//) {
                url = orig_title
            }
        }

        # Pass 5: Collect all remaining unused lines into comment
        comment = ""
        for (i = 1; i <= total; i++) {
            if (!used[i]) {
                if (comment == "") {
                    comment = lines[i]
                } else {
                    comment = comment "\n" lines[i]
                }
            }
        }

        # Header lines for shell processing
        print "META_TITLE:" title
        print "META_ACCOUNT:" acc
        print "META_URL:" url

        # Standardized YAML Body
        print "password: " yaml_quote(pass)
        print "title: " yaml_quote(title)
        if (acc != "") {
            print "account: " yaml_quote(acc)
        }
        if (url != "") {
            print "url: " yaml_quote(url)
        }
        if (otp != "") {
            print "otp: " yaml_quote(otp)
        }
        print "created_at: " yaml_quote(now)
        print "updated_at: " yaml_quote(now)

        if (trim(comment) != "") {
            print "comment: |"
            n = split(comment, clines, "\n")
            for (j = 1; j <= n; j++) {
                print "  " clines[j]
            }
        }
    }')

    # STREAMING_CHUNK:Deriving anti-forensic hashes and destination paths...
    val_title=$(echo "$parsed_output" | sed -n '1p' | sed 's/^META_TITLE://')
    val_acc=$(echo "$parsed_output" | sed -n '2p' | sed 's/^META_ACCOUNT://')
    val_url=$(echo "$parsed_output" | sed -n '3p' | sed 's/^META_URL://')
    yaml_payload=$(echo "$parsed_output" | tail -n +4)

    # Compute 16-character SHA-256 hash for anti-forensic filename
    if [ -n "$val_acc" ]; then
        hash_name=$(printf "%s" "$val_acc" | sha256sum | awk '{print substr($1, 1, 16)}')
    else
        hash_name=$(printf "%s" "$base_name" | sha256sum | awk '{print substr($1, 1, 16)}')
    fi

    if [ "$rel_dir" = "." ]; then
        target_subdir="$DST_DIR"
        display_rel="$hash_name.yaml.gpg"
    else
        target_subdir="$DST_DIR/$rel_dir"
        display_rel="$rel_dir/$hash_name.yaml.gpg"
    fi
    target_file="$target_subdir/$hash_name.yaml.gpg"

    # STREAMING_CHUNK:Executing dry-run or writing encrypted credentials...
    if [ "$DRY_RUN" -eq 1 ]; then
        echo "[DRY-RUN] $rel_path -> $display_rel"
        echo "          Title: $val_title | Account: ${val_acc:-(none)} | URL: ${val_url:-(none)}"
        continue
    fi

    mkdir -p "$target_subdir"
    chmod 700 "$target_subdir"

    # Encrypt directly into destination without temporary plaintext files
    echo "$yaml_payload" | gpg --batch --yes --encrypt --throw-keyids \
        "${GPG_RECIPIENT_ARGS[@]}" \
        -o "$target_file"

    # Strict permissions and temporal sanitization
    chmod 600 "$target_file"
    touch -d @0 "$target_file"
    touch -d @0 "$target_subdir"

    echo "Migrated: $rel_path -> $display_rel (Title: $val_title)"
    migrated_count=$((migrated_count + 1))

    # STREAMING_CHUNK:Optionally shredding legacy source files...
    if [ "$SHRED_OLD" -eq 1 ]; then
        if command -v shred >/dev/null 2>&1; then
            shred -u -z "$src_file"
        else
            rm -f "$src_file"
        fi
    fi

done < <(find "$SRC_DIR" -type f -name "*.gpg" -print0)

# STREAMING_CHUNK:Sanitizing root store timestamps and displaying summary...
if [ "$DRY_RUN" -eq 0 ]; then
    touch -d @0 "$DST_DIR"
    if [ -f "$DST_DIR/.gpg-id" ]; then
        touch -d @0 "$DST_DIR/.gpg-id"
    fi
fi

echo "--------------------------------------------------------"
echo "==> Migration finished."
echo "==> Total scanned: $total_count"
if [ "$DRY_RUN" -eq 1 ]; then
    echo "==> Dry-run completed. No files were modified."
else
    echo "==> Migrated:      $migrated_count"
    echo "==> Skipped:       $skipped_count"
fi
echo "--------------------------------------------------------"