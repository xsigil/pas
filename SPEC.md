# pas — Architecture & OpSec Specification (v1.0.0)

`pas` は、Wayland/Hyprland (Arch Linux) 環境に最適化され、ファイルシステム層・トポロジー層・時間軸・端末表示におけるメタデータ漏洩とサイドチャネル解析を徹底排除した、Go 製の単一バイナリ・パスワードマネージャーです。

---

## 1. コア原則（設計思想）

1. **ゼロ・メタデータ露出（Zero-Metadata Exposure）**
   * ディスク上および Git 履歴において、平文のアカウント名・メールアドレス・サービス固有識別子を 1 バイトも残さない。
   * エントリのファイル名は `sha256(account)[:16].yaml.gpg` を強制する。
2. **時間軸フォレンジック防御（Temporal Anti-Forensics）**
   * ファイルシステム上の `atime` および `mtime` はすべて **UNIX Epoch 原点（`1970-01-01 00:00:00 UTC`）** に強制上書き。
   * 更新頻度・生活リズム・外部イベントとの相関解析を遮断する。真のタイムスタンプ（`created_at`, `updated_at`）は暗号化 YAML ペイロード内部にのみ秘匿保持する。
3. **プロセスレベルのパーミッション強制（umask 0077）**
   * プロセス初期化時（`init()`）に `syscall.Umask(0077)` を実行。
   * ディレクトリ `0700` (`drwx------`)、ファイル `0600` (`-rw-------`) を強制し、権限緩み（パーミッション・スリップ）を物理的に遮断する。
4. **標準出力ダンプの原則禁止（No-Stdout Policy）**
   * 画面盗み見（ショルダーハック）、シェル履歴、tmux バッファ汚染を防止するため、stdout への平文出力を拒絶。
   * デフォルトは Wayland のクリップボード（`wl-copy -n`）へ直接転送し、指定時間（デフォルト 45 秒）で自動消滅させる。平文表示は明示的な `-p` / `--print` フラグ時のみに限定。
5. **インメモリ解錠 ＋ 平文検索**
   * 使用時のみ `gpg-agent` 経由でメモリ（`/dev/shm` / RAM）上にインデックスを並列展開し、`fzf` で平文検索を実行する。
6. **自己主権トポロジー（Anti-Cloud & Mesh Sync）**
   * GitHub や商用クラウドへの push は厳禁。
   * 同期はプライベートメッシュ（WireGuard）上の自前ノード（`hq1`/`hq2`）のベア Git リポジトリのみで行う。
   * コールドバックアップは構造・件数を不可視化する単一暗号化アーカイブ（`tar.bz2.gpg`）を使用。
7. **プログレッシブ・マイグレーション（段階的移行）**
   * 新形式 `.yaml.gpg`（キー名指定）と旧形式 `.gpg`（`-c n` 行番号指定）を拡張子で自動判別。
   * 旧 `~/.password-store` から新 `~/.pastore` への自動変換・安全消去を行う `migrate` サブコマンドを標準搭載。

---

## 2. ストレージ & 暗号化仕様

### ストア配置
* **デフォルトパス:** `~/.pastore`
* **環境変数オーバーライド:** `PASTORE_DIR`（未指定時は `~/.pastore` を自動解決）
* **シグネチャ隠蔽:** 既知のパスワード探索パス（`~/.password-store`）を排除し、静的スキャンから退避。

### ディレクトリ構造 & ファイル命名

```text
~/.pastore/
├── .gpg-id                             # 受信者公開鍵ID (0600 / Epoch Zero)
├── personal/
│   └── [github.com/](https://github.com/)
│       ├── 3a7f8b9c0d1e2f3a.yaml.gpg   # sha256(account)[:16].yaml.gpg (0600 / Epoch Zero)
│       └── LegacyEntry.gpg             # 未移行エントリ (0600 / Epoch Zero)
└── infra/
    └── router/
        └── 7b2c4a9f1e0d8a5e.yaml.gpg   # (0600 / Epoch Zero)

```

* **ハッシュ導出アルゴリズム:**

$$\text{hash} = \text{SHA256}(\text{account})[0:16]$$



メールアドレスや識別子から 64-bit 空間の 16 進ハッシュを導出し、ファイル名とする。
* **暗号化オプション:**
* 受信者鍵 ID の漏洩を防ぐため、暗号化時は `gpg --throw-keyids` を標準適用。



### 内部ペイロードスキーマ（`.yaml.gpg`）

```yaml
password: "randomly-generated-secret-string"
account: "sugaya.masahiro@gmail.com"
url: "[https://github.com](https://github.com)"
otp: "JBSWY3DPEHPK3PXP" # RFC 6238 準拠 TOTP シークレット
created_at: "2026-10-03T05:50:00Z" # 真の作成日時
updated_at: "2026-10-03T05:50:00Z" # 真の更新日時
comment: |
  Personal production account.
  Linked with ED25519 hardware token.
meta:
  pin: "1234"

```

---

## 3. CLI インターフェース仕様

```text
pas [options] [target] [key]
pas <subcommand> [options] [args]

```

### コマンド・引数体系

| 実行コマンド | 挙動 |
| --- | --- |
| `pas` | インメモリ解錠を行い、`fzf` で対話検索。確定したエントリの `password` をクリップボードへコピー |
| `pas <target>` | 指定エントリの `password` をクリップボードへコピー（stdout 出力ゼロ） |
| `pas <target> <key>` | 指定エントリの任意キー（`account`, `url`, `otp`, `pin` 等）をクリップボードへコピー |
| `pas -c <N> <target>` | **レガシー互換**: 旧形式 `.gpg` の $N$ 行目をクリップボードへコピー（デフォルト: 1行目） |
| `pas -p <target> [key]` | **平文確認モード**: 指定キーまたは YAML 全文を `stdout` に表示 |
| `pas generate -H <account> <dir>` | アカウント名からハッシュファイル名を自動算出し、ランダムパスワード入り YAML を生成・Epoch Zero 適用 |
| `pas edit <target>` | RAM（`/dev/shm`）上で安全に復号・編集・構文検証し、再暗号化後に Epoch Zero を再設定 |
| `pas rm [-r] <target>` | ディスク領域をゼロ／乱数で上書き消去（shred 相当）した後に削除（Git 追跡時は `git rm`） |
| `pas mv <src> <dst>` | エントリの移動・リネーム（Git 追跡下であれば履歴を保持） |
| `pas migrate [options]` | 旧ストア（`~/.password-store`）の `.gpg` を `.yaml.gpg`（ハッシュファイル名）へ一括／個別移行 |
| `pas audit` | パーミッション（`0700`/`0600` 以外）、非ゼロタイムスタンプ、ハッシュ不整合、脆弱・重複パスワードの検査と自動修復 |

---

## 4. 内部アーキテクチャ & パイプライン

### インメモリ解錠 ＋ fzf 検索フロー

```text
[ Disk: Hash Files (.yaml.gpg) ] (Dir: 0700 / File: 0600 / mtime: 1970-01-01)
              │
              │  並列 goroutine (Worker Pool: runtime.NumCPU() * 2)
              ▼
[ Decrypt in Memory (/dev/shm) ] ── (gpg --decrypt / gpg-agent)
              │
              │  パース: Service Path + Account + Key Names
              ▼
[ fzf Interactive UI ]
   > git masahiro
   ──────────────────────────────────────────────────────────────────────────
   > personal/github.com  │  sugaya.masahiro@gmail.com  │  (3a7f8b9c0d1e2f3a)
     corp/github.com      │  corp-admin@section9.jp     │  (7b2c4a9f1e0d8a5e)
   ──────────────────────────────────────────────────────────────────────────
              │
              ├── Enter   ──> wl-copy (password)
              ├── Ctrl-Y  ──> wl-copy (account)
              └── Ctrl-O  ──> RFC 6238 TOTP 計算 ──> wl-copy
              │
              ▼
[ Background Timer ] ── (45秒後に wl-copy --clear を非同期実行)

```

---

## 5. セキュリティ & パーミッション防壁

1. **プロセス起動時のハードニング**
* プロセスの初期化フェーズ（`init()`）で `syscall.Umask(0077)` を実行。
* 新規作成されるディレクトリは `0700`、ファイルは `0600` を強制。


2. **タイムスタンプ抹消ロジック（`os.Chtimes`）**
* ファイル作成・更新・インポート完了時に直ちに `os.Chtimes(path, time.Unix(0, 0), time.Unix(0, 0))` を実行。
* `pas audit --fix` で全エントリのタイムスタンプを一括でエポック原点にリセット。


3. **インプレース・セキュア消去**
* `pas rm` や `pas migrate` での旧ファイル破棄時は、乱数上書きによるデータ消去を行ってから `unlink`。


4. **Wayland クリップボード保護**
* `wl-copy -n` 直結。標準出力汚染とシェル履歴保存を防止し、45 秒の非同期タイマーでクリア。



---

## 6. レガシー・マイグレーション仕様（`pas migrate`）

```text
pas migrate [--from <old_store>] [--to <new_store>] [--all] [--dry-run] [target]

```

### 変換アルゴリズム

1. 旧 `.gpg` を復号し、行構造を解析：
* **1 行目:** `password`
* **2 行目:** アカウント名（`account:` / `user:` / `email:` プレフィックス解析、または 2 行目をそのまま採用）
* **3 行目以降:** `comment` フィールドに集約


2. アカウント名から `sha256(account)[:16]` を算出（アカウント名不在時は元ファイル名をフォールバック）。
3. YAML ペイロードを構成（真のタイムスタンプとして `created_at` を注入）。
4. 新ストア（`~/.pastore`）へ `0600` で暗号化保存（`--throw-keyids` 適用）。
5. ファイルのタイムスタンプを Epoch Zero（`1970-01-01 00:00:00 UTC`）に上書き。
6. 旧ファイルを乱数上書きによりセキュア消去（shred 相当）。

---

## 7. 同期・インフラ構成（OpSec トポロジー）

```text
                           [ Local: XPS 13 ]
                            (Arch / Hyprland)
                                   │
                 ┌─────────────────┴─────────────────┐
                 │ Hot Sync                          │ Cold Backup
                 │ (WireGuard Only)                  │ (Tarball Blob)
                 ▼                                   ▼
     [ hq1 / hq2 Nodes ]                     [ Offline SSD / Cold Storage ]
     /srv/git/pastore.git (Bare Repo)        pastore_backup_YYYYMMDD.tar.bz2.gpg
     - 外部公開ポート完全ゼロ                 - 全体のディレクトリ構造・個数を隠蔽
     - 差分追跡とマシン間即時同期             - 単一バイナリ塊によるトラフィック解析遮断

```

* **Git 履歴の完全漂白:**
移行完了後、旧ストアのコミット履歴（平文ファイル名を含む過去ログ）は引き継がず、`~/.pastore` 内で新規 `git init` を実行し、完全ハッシュ化された状態を 1st コミットとする。

---

## 8. 実装ロードマップ

1. **Phase 1: コアバイナリ・エンジンの構築**
* `syscall.Umask(0077)` の組み込み
* `~/.pastore` パス解決と YAML / 行指向ハイブリッドローダー
* `wl-copy -n` 直結と 45 秒クリアタイマー
* Epoch Zero タイムスタンプ上書き関数（`sanitizeTimestamps()`）


2. **Phase 2: サブコマンド群の実装**
* `pas generate -H`（ハッシュファイル名自動算出・YAML 生成）
* 並列インメモリ復号ワーカー ＋ `fzf` インターフェース統合
* `pas edit`（RAM 上での安全編集 ＋ YAML 構文バリデーション）
* `pas rm`（セキュア消去）および `pas audit`（権限・タイムスタンプ自動修復）


3. **Phase 3: マイグレーション & ベア Git 同期確立**
* `pas migrate` による旧 `~/.password-store` からの新ツリー生成
* `~/.pastore` の新規 `git init` と初回クリーンコミット
* `hq1` / `hq2` のベア Git への WireGuard 経由 push
* コールドバックアップ（`tar.bz2.gpg`）スクリプトの配置

