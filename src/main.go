package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// EpochZero is the canonical fixed timestamp used to eliminate temporal forensic trace.
var EpochZero = time.Unix(0, 0).UTC()

const (
	DirPermSecure   = 0700
	FilePermSecure  = 0600
	DefaultClearSec = 45
	VaultFileName   = "vault.yaml.gpg"
	GpgIdFileName   = ".gpg-id"

	ColWidthPath    = 44
	ColWidthTitle   = 22
	ColWidthAccount = 26
)

// init guarantees that under any code execution path, umask 0077 is active.
func init() {
	syscall.Umask(0077)
}

// Entry represents a single credential record inside the monolithic encrypted vault.
type Entry struct {
	Path      string            `yaml:"path"`
	Title     string            `yaml:"title,omitempty"`
	Account   string            `yaml:"account,omitempty"`
	URL       string            `yaml:"url,omitempty"`
	Password  string            `yaml:"password"`
	OTP       string            `yaml:"otp,omitempty"`
	CreatedAt string            `yaml:"created_at,omitempty"`
	UpdatedAt string            `yaml:"updated_at,omitempty"`
	Comment   string            `yaml:"comment,omitempty"`
	Meta      map[string]string `yaml:"meta,omitempty"`
}

// Vault represents the entire encrypted database payload.
type Vault struct {
	Version   int      `yaml:"version"`
	UpdatedAt string   `yaml:"updated_at"`
	Entries   []*Entry `yaml:"entries"`
}

type CryptoService interface {
	Decrypt(gpgPath, storeDir string) ([]byte, error)
	Encrypt(recipients []string, plaintext []byte, outputPath string) error
	GetRecipients(storeDir string) ([]string, error)
}

type ClipboardService interface {
	Copy(content string, clearSec int) error
}

type GPGService struct{}

func NewGPGService() *GPGService {
	return &GPGService{}
}

func (g *GPGService) Decrypt(gpgPath, storeDir string) ([]byte, error) {
	args := []string{"--quiet", "--batch"}

	// Specify explicit recipient keys to prevent scanning unnecessary keyrings
	if recipients, err := g.GetRecipients(storeDir); err == nil {
		for _, r := range recipients {
			args = append(args, "--try-secret-key", r)
		}
	}
	args = append(args, "--decrypt", gpgPath)

	cmd := exec.Command("gpg", args...)
	cmd.Stdin = os.Stdin

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gpg decrypt failed: %s (%w)", strings.TrimSpace(stderr.String()), err)
	}
	return stdout.Bytes(), nil
}

func (g *GPGService) Encrypt(recipients []string, plaintext []byte, outputPath string) error {
	args := []string{"--quiet", "--batch", "--yes", "--encrypt", "--throw-keyids"}
	for _, r := range recipients {
		args = append(args, "-r", r)
	}
	args = append(args, "-o", outputPath)

	cmd := exec.Command("gpg", args...)
	cmd.Stdin = bytes.NewReader(plaintext)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("gpg encrypt failed: %s (%w)", strings.TrimSpace(stderr.String()), err)
	}
	return nil
}

func (g *GPGService) GetRecipients(storeDir string) ([]string, error) {
	idPath := filepath.Join(storeDir, GpgIdFileName)
	data, err := os.ReadFile(idPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read %s: %w", GpgIdFileName, err)
	}

	var recipients []string
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
			recipients = append(recipients, trimmed)
		}
	}
	if len(recipients) == 0 {
		return nil, errors.New(".gpg-id contains no valid recipients")
	}
	return recipients, nil
}

type WaylandClipboardService struct{}

func NewWaylandClipboardService() *WaylandClipboardService {
	return &WaylandClipboardService{}
}

func (w *WaylandClipboardService) Copy(content string, clearSec int) error {
	cmd := exec.Command("wl-copy", "-n")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to open wl-copy stdin pipe: %w", err)
	}

	go func() {
		defer stdin.Close()
		_, _ = io.WriteString(stdin, content)
	}()

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("wl-copy execution failed: %w", err)
	}

	if clearSec > 0 {
		go func() {
			time.Sleep(time.Duration(clearSec) * time.Second)
			_ = exec.Command("wl-copy", "--clear").Run()
		}()
	}
	return nil
}

type VaultRepository struct {
	storeDir  string
	vaultPath string
	crypto    CryptoService
}

func NewVaultRepository(crypto CryptoService) *VaultRepository {
	dir := os.Getenv("PASTORE_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot resolve user home directory: %v\n", err)
			os.Exit(1)
		}
		dir = filepath.Join(home, ".pastore")
	}
	_ = os.MkdirAll(dir, DirPermSecure)
	return &VaultRepository{
		storeDir:  dir,
		vaultPath: filepath.Join(dir, VaultFileName),
		crypto:    crypto,
	}
}

func (r *VaultRepository) GetStoreDir() string {
	return r.storeDir
}

func (r *VaultRepository) VaultExists() bool {
	_, err := os.Stat(r.vaultPath)
	return err == nil
}

func (r *VaultRepository) LoadVault() (*Vault, error) {
	if !r.VaultExists() {
		return &Vault{Version: 1, UpdatedAt: time.Now().UTC().Format(time.RFC3339)}, nil
	}

	raw, err := r.crypto.Decrypt(r.vaultPath, r.storeDir)
	if err != nil {
		return nil, err
	}

	var vault Vault
	if err := yaml.Unmarshal(raw, &vault); err != nil {
		return nil, fmt.Errorf("failed to parse vault YAML: %w", err)
	}
	return &vault, nil
}

func (r *VaultRepository) SaveVault(v *Vault) error {
	v.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	payload, err := yaml.Marshal(v)
	if err != nil {
		return fmt.Errorf("failed to encode vault YAML: %w", err)
	}

	recipients, err := r.crypto.GetRecipients(r.storeDir)
	if err != nil {
		return err
	}

	// Atomic write via temporary file
	tmpPath := filepath.Join(r.storeDir, fmt.Sprintf(".vault-tmp-%d.gpg", time.Now().UnixNano()))
	if err := r.crypto.Encrypt(recipients, payload, tmpPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}

	_ = os.Chmod(tmpPath, FilePermSecure)

	// Atomic replace
	if err := os.Rename(tmpPath, r.vaultPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("failed to replace vault: %w", err)
	}

	// Immediate temporal sanitization
	_ = os.Chtimes(r.vaultPath, EpochZero, EpochZero)
	_ = os.Chtimes(r.storeDir, EpochZero, EpochZero)
	return nil
}

type VaultUseCase struct {
	repo      *VaultRepository
	clipboard ClipboardService
}

func NewVaultUseCase(repo *VaultRepository, clip ClipboardService) *VaultUseCase {
	return &VaultUseCase{repo: repo, clipboard: clip}
}

// fitColumn safely truncates long strings with an ellipsis and pads to target width
func fitColumn(s string, width int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) > width {
		if width <= 1 {
			return string(r[:width])
		}
		return string(r[:width-1]) + "…"
	}
	return s + strings.Repeat(" ", width-len(r))
}

func (uc *VaultUseCase) InteractiveSearch(clearSec int) error {
	vault, err := uc.repo.LoadVault()
	if err != nil {
		return err
	}

	if len(vault.Entries) == 0 {
		return errors.New("vault is empty")
	}

	var lines []string
	entryLookup := make([]*Entry, len(vault.Entries))

	for idx, e := range vault.Entries {
		entryLookup[idx] = e
		colPath := fitColumn(e.Path, ColWidthPath)
		colTitle := fitColumn(e.Title, ColWidthTitle)
		colAcc := fitColumn(e.Account, ColWidthAccount)

		// Format line with a trailing tab-separated hidden index for zero-ambiguity retrieval
		formatted := fmt.Sprintf("%s  │  %s  │  %s  │  %s\t#%d", colPath, colTitle, colAcc, e.URL, idx)
		lines = append(lines, formatted)
	}

	selectedLine, action, err := uc.runFzfUI(lines)
	if err != nil {
		return nil // Clean cancellation
	}

	tabIdx := strings.LastIndex(selectedLine, "\t#")
	if tabIdx == -1 {
		return errors.New("malformed fzf selection")
	}

	idxVal, err := strconv.Atoi(selectedLine[tabIdx+2:])
	if err != nil || idxVal < 0 || idxVal >= len(entryLookup) {
		return errors.New("selected item not found in vault")
	}

	chosen := entryLookup[idxVal]

	targetValue := chosen.Password
	targetLabel := "password"

	switch action {
	case "ctrl-y":
		targetValue = chosen.Account
		targetLabel = "account"
	case "ctrl-t":
		targetValue = chosen.Title
		targetLabel = "title"
	case "ctrl-u":
		targetValue = chosen.URL
		targetLabel = "url"
	case "ctrl-o":
		targetValue = chosen.OTP
		targetLabel = "otp"
	}

	if targetValue == "" {
		return fmt.Errorf("%s is empty for this entry", targetLabel)
	}

	if err := uc.clipboard.Copy(targetValue, clearSec); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Copied %s to clipboard (clears in %ds).\n", targetLabel, clearSec)
	return nil
}

func (uc *VaultUseCase) Retrieve(targetPath, field string, printOnly bool, clearSec int) error {
	vault, err := uc.repo.LoadVault()
	if err != nil {
		return err
	}

	var match *Entry
	targetClean := strings.Trim(targetPath, "/")
	for _, e := range vault.Entries {
		if strings.Trim(e.Path, "/") == targetClean {
			match = e
			break
		}
	}

	if match == nil {
		return fmt.Errorf("entry not found: %s", targetPath)
	}

	if printOnly && field == "" {
		out, _ := yaml.Marshal(match)
		fmt.Print(string(out))
		return nil
	}

	val := match.Password
	label := "password"

	if field != "" {
		label = strings.ToLower(field)
		switch label {
		case "account", "user", "username":
			val = match.Account
		case "title", "name":
			val = match.Title
		case "url", "link":
			val = match.URL
		case "otp", "totp":
			val = match.OTP
		case "password", "pass":
			val = match.Password
		case "comment", "notes":
			val = match.Comment
		default:
			if match.Meta != nil {
				if mv, ok := match.Meta[label]; ok {
					val = mv
				} else {
					return fmt.Errorf("field '%s' not found", field)
				}
			} else {
				return fmt.Errorf("field '%s' not found", field)
			}
		}
	}

	if printOnly {
		fmt.Println(val)
		return nil
	}

	if err := uc.clipboard.Copy(val, clearSec); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Copied %s to clipboard (clears in %ds).\n", label, clearSec)
	return nil
}

func (uc *VaultUseCase) Generate(path, account, title, url string, length, clearSec int) error {
	if length <= 0 {
		length = 24
	}

	password, err := generateCryptographicPassword(length)
	if err != nil {
		return err
	}

	vault, err := uc.repo.LoadVault()
	if err != nil {
		return err
	}

	now := time.Now().UTC().Format(time.RFC3339)
	cleanPath := strings.Trim(path, "/")

	var existing *Entry
	for _, e := range vault.Entries {
		if strings.Trim(e.Path, "/") == cleanPath {
			existing = e
			break
		}
	}

	if existing != nil {
		existing.Password = password
		existing.UpdatedAt = now
		if account != "" {
			existing.Account = account
		}
		if title != "" {
			existing.Title = title
		}
		if url != "" {
			existing.URL = url
		}
	} else {
		if title == "" {
			title = filepath.Base(cleanPath)
		}
		vault.Entries = append(vault.Entries, &Entry{
			Path:      cleanPath,
			Title:     title,
			Account:   account,
			URL:       url,
			Password:  password,
			CreatedAt: now,
			UpdatedAt: now,
		})
	}

	if err := uc.repo.SaveVault(vault); err != nil {
		return err
	}

	if err := uc.clipboard.Copy(password, clearSec); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Saved entry: %s\n", cleanPath)
	fmt.Fprintf(os.Stderr, "Copied password to clipboard (clears in %ds).\n", clearSec)
	return nil
}

func (uc *VaultUseCase) Move(src, dst string) error {
	vault, err := uc.repo.LoadVault()
	if err != nil {
		return err
	}

	srcClean := strings.Trim(src, "/")
	dstClean := strings.Trim(dst, "/")

	movedCount := 0
	for _, e := range vault.Entries {
		entryClean := strings.Trim(e.Path, "/")
		if entryClean == srcClean {
			e.Path = dstClean
			e.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			movedCount++
		} else if strings.HasPrefix(entryClean, srcClean+"/") {
			rel := strings.TrimPrefix(entryClean, srcClean+"/")
			e.Path = dstClean + "/" + rel
			e.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
			movedCount++
		}
	}

	if movedCount == 0 {
		return fmt.Errorf("source path '%s' not found", src)
	}

	if err := uc.repo.SaveVault(vault); err != nil {
		return err
	}

	fmt.Printf("Moved %d entry/entries from '%s' to '%s'\n", movedCount, src, dst)
	return nil
}

func (uc *VaultUseCase) Remove(target string, recursive bool) error {
	vault, err := uc.repo.LoadVault()
	if err != nil {
		return err
	}

	targetClean := strings.Trim(target, "/")
	var remaining []*Entry
	removedCount := 0

	for _, e := range vault.Entries {
		entryClean := strings.Trim(e.Path, "/")
		if entryClean == targetClean {
			removedCount++
		} else if strings.HasPrefix(entryClean, targetClean+"/") {
			if recursive {
				removedCount++
			} else {
				remaining = append(remaining, e)
			}
		} else {
			remaining = append(remaining, e)
		}
	}

	if removedCount == 0 {
		return fmt.Errorf("path '%s' not found", target)
	}

	vault.Entries = remaining
	if err := uc.repo.SaveVault(vault); err != nil {
		return err
	}

	fmt.Printf("Removed %d entry/entries.\n", removedCount)
	return nil
}

func (uc *VaultUseCase) Migrate(sourceDir string) error {
	if sourceDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		sourceDir = filepath.Join(home, ".password-store")
	}

	if _, err := os.Stat(sourceDir); err != nil {
		return fmt.Errorf("source store directory not found: %s", sourceDir)
	}

	var files []string
	err := filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(sourceDir, path)
		if strings.HasPrefix(rel, ".git") || rel == ".gpg-id" || strings.HasSuffix(rel, ".yaml.gpg") {
			return nil
		}
		if strings.HasSuffix(path, ".gpg") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(files)

	if len(files) == 0 {
		return errors.New("no legacy .gpg entries found in source directory")
	}

	nowUTC := time.Now().UTC().Format(time.RFC3339)
	vault := &Vault{
		Version:   1,
		UpdatedAt: nowUTC,
		Entries:   make([]*Entry, 0, len(files)),
	}

	fmt.Fprintf(os.Stderr, "==> Migrating %d legacy entries into monolithic vault...\n", len(files))

	migrated := 0
	skipped := 0

	for idx, f := range files {
		raw, err := uc.repo.crypto.Decrypt(f, uc.repo.storeDir)
		if err != nil {
			raw, err = uc.repo.crypto.Decrypt(f, sourceDir)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[SKIP] (%d/%d) Decrypt failed: %s (%v)\n", idx+1, len(files), filepath.Base(f), err)
			skipped++
			continue
		}

		relPath, _ := filepath.Rel(sourceDir, f)
		cleanPath := strings.TrimSuffix(relPath, ".gpg")
		baseName := filepath.Base(cleanPath)

		entry := parseLegacyContent(raw, cleanPath, baseName, nowUTC)
		vault.Entries = append(vault.Entries, entry)
		migrated++
		fmt.Fprintf(os.Stderr, "[%d/%d] Indexed: %s (Title: %s)\n", migrated, len(files), cleanPath, entry.Title)
	}

	if err := uc.repo.SaveVault(vault); err != nil {
		return fmt.Errorf("failed to save monolithic vault: %w", err)
	}

	fmt.Fprintf(os.Stderr, "--------------------------------------------------------\n")
	fmt.Fprintf(os.Stderr, "==> Migration complete!\n")
	fmt.Fprintf(os.Stderr, "==> Total entries encrypted: %d\n", migrated)
	fmt.Fprintf(os.Stderr, "==> Vault file: %s (Permissions: 0600, Timestamp: 1970-01-01)\n", uc.repo.vaultPath)
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "==> Skipped %d undecryptable entries.\n", skipped)
	}
	return nil
}

func parseLegacyContent(raw []byte, path, baseName, now string) *Entry {
	// Normalize CRLF to LF to prevent YAML indentation poison
	content := strings.ReplaceAll(string(raw), "\r\n", "\n")
	content = strings.ReplaceAll(content, "\r", "\n")

	lines := strings.Split(content, "\n")
	used := make([]bool, len(lines))

	var pass, title, acc, url, otp string

	// Pass 1: Extract labeled fields
	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		lower := strings.ToLower(trimmed)
		switch {
		case strings.HasPrefix(lower, "password:") || strings.HasPrefix(lower, "pass:"):
			idx := strings.Index(trimmed, ":")
			if pass == "" {
				pass = strings.TrimSpace(trimmed[idx+1:])
				used[i] = true
			}
		case strings.HasPrefix(lower, "title:") || strings.HasPrefix(lower, "name:") || strings.HasPrefix(lower, "service_name:"):
			idx := strings.Index(trimmed, ":")
			if title == "" {
				title = strings.TrimSpace(trimmed[idx+1:])
				used[i] = true
			}
		case strings.HasPrefix(lower, "account:") || strings.HasPrefix(lower, "user:") || strings.HasPrefix(lower, "username:") || strings.HasPrefix(lower, "email:") || strings.HasPrefix(lower, "login:"):
			idx := strings.Index(trimmed, ":")
			if acc == "" {
				acc = strings.TrimSpace(trimmed[idx+1:])
				used[i] = true
			}
		case strings.HasPrefix(lower, "url:") || strings.HasPrefix(lower, "uri:") || strings.HasPrefix(lower, "link:") || strings.HasPrefix(lower, "service:"):
			idx := strings.Index(trimmed, ":")
			if url == "" {
				url = strings.TrimSpace(trimmed[idx+1:])
				used[i] = true
			}
		case strings.HasPrefix(lower, "otp:") || strings.HasPrefix(lower, "totp:"):
			idx := strings.Index(trimmed, ":")
			if otp == "" {
				otp = strings.TrimSpace(trimmed[idx+1:])
				used[i] = true
			}
		case strings.HasPrefix(lower, "otpauth://"):
			if otp == "" {
				otp = trimmed
				used[i] = true
			}
		}
	}

	// Pass 2: Positional password (first unused line)
	if pass == "" {
		for i, line := range lines {
			t := strings.TrimSpace(line)
			if !used[i] && t != "" {
				pass = t
				used[i] = true
				break
			}
		}
	}

	// Pass 3: Positional account (second unused line)
	if acc == "" {
		for i, line := range lines {
			t := strings.TrimSpace(line)
			if !used[i] && t != "" && !strings.HasPrefix(t, "---") {
				acc = t
				used[i] = true
				break
			}
		}
	}

	// Pass 4: Fallback title to original filename base
	if title == "" {
		title = baseName
	}

	// Pass 5: Domain detection for URL
	if url == "" {
		if strings.HasPrefix(baseName, "http://") || strings.HasPrefix(baseName, "https://") {
			url = baseName
		} else {
			domainSuffixes := []string{".com", ".org", ".net", ".io", ".jp", ".me", ".ltd", ".la", ".dev", ".info", ".biz", ".co", ".app", ".local"}
			lowerBase := strings.ToLower(baseName)
			for _, s := range domainSuffixes {
				if strings.Contains(lowerBase, s) {
					url = baseName
					break
				}
			}
		}
	}

	// Pass 6: Collect remaining unused lines into Comment
	var commentLines []string
	for i, line := range lines {
		if !used[i] {
			commentLines = append(commentLines, line)
		}
	}
	comment := strings.TrimSpace(strings.Join(commentLines, "\n"))

	return &Entry{
		Path:      path,
		Title:     title,
		Account:   acc,
		URL:       url,
		Password:  pass,
		OTP:       otp,
		CreatedAt: now,
		UpdatedAt: now,
		Comment:   comment,
	}
}

func (uc *VaultUseCase) Audit() error {
	storeDir := uc.repo.GetStoreDir()
	fmt.Fprintf(os.Stderr, "==> Auditing monolithic store at %s...\n", storeDir)

	fixedPerms := 0
	fixedTimes := 0

	err := filepath.Walk(storeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		mode := info.Mode().Perm()
		if info.IsDir() {
			if mode != DirPermSecure {
				_ = os.Chmod(path, DirPermSecure)
				fixedPerms++
			}
		} else {
			if mode != FilePermSecure {
				_ = os.Chmod(path, FilePermSecure)
				fixedPerms++
			}
			if !info.ModTime().Equal(EpochZero) {
				_ = os.Chtimes(path, EpochZero, EpochZero)
				fixedTimes++
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Audit complete.\nPermissions normalized (0700/0600): %d\nTimestamps reset to EpochZero: %d\n", fixedPerms, fixedTimes)
	return nil
}

func (uc *VaultUseCase) Export() error {
	vault, err := uc.repo.LoadVault()
	if err != nil {
		return err
	}
	out, err := yaml.Marshal(vault)
	if err != nil {
		return err
	}
	fmt.Print(string(out))
	return nil
}

func (uc *VaultUseCase) runFzfUI(lines []string) (string, string, error) {
	cmd := exec.Command("fzf",
		"--height=40%",
		"--reverse",
		"--prompt=pas > ",
		"--header=Enter: password | Ctrl-T: title | Ctrl-Y: account | Ctrl-U: url | Ctrl-O: otp",
		"--expect=ctrl-t,ctrl-y,ctrl-u,ctrl-o",
		"--delimiter=\t",
		"--with-nth=1",
	)
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n"))
	cmd.Stderr = os.Stderr

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", "", err
	}

	raw := strings.TrimRight(stdout.String(), "\r\n")
	parts := strings.Split(raw, "\n")
	if len(parts) < 2 {
		return "", "", errors.New("empty selection")
	}

	return parts[1], parts[0], nil
}

func generateCryptographicPassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}<>?"
	result := make([]byte, length)
	charsetLen := big.NewInt(int64(len(charset)))
	for i := range result {
		idx, err := rand.Int(rand.Reader, charsetLen)
		if err != nil {
			return "", err
		}
		result[i] = charset[idx.Int64()]
	}
	return string(result), nil
}

var version = "2.0.1"

func main() {
	crypto := NewGPGService()
	repo := NewVaultRepository(crypto)
	clip := NewWaylandClipboardService()
	app := NewVaultUseCase(repo, clip)

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate":
			runMigrateCLI(app, os.Args[2:])
			return
		case "generate":
			runGenerateCLI(app, os.Args[2:])
			return
		case "mv":
			runMoveCLI(app, os.Args[2:])
			return
		case "rm":
			runRemoveCLI(app, os.Args[2:])
			return
		case "audit":
			if err := app.Audit(); err != nil {
				fmt.Fprintf(os.Stderr, "Audit failed: %v\n", err)
				os.Exit(1)
			}
			return
		case "export":
			if err := app.Export(); err != nil {
				fmt.Fprintf(os.Stderr, "Export failed: %v\n", err)
				os.Exit(1)
			}
			return
		case "version", "--version":
			fmt.Printf("pas v%s (Monolithic Vault / Wayland Native)\n", version)
			return
		}
	}

	runDefaultCLI(app, os.Args[1:])
}

func runMigrateCLI(app *VaultUseCase, args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	var fromDir string
	fs.StringVar(&fromDir, "from", "", "Source password-store directory (defaults to ~/.password-store)")
	_ = fs.Parse(args)

	if err := app.Migrate(fromDir); err != nil {
		fmt.Fprintf(os.Stderr, "Migration error: %v\n", err)
		os.Exit(1)
	}
}

func runDefaultCLI(app *VaultUseCase, args []string) {
	var (
		printFlag bool
		clearSec  int = DefaultClearSec
		cleanArgs []string
	)

	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "-p" || arg == "--print":
			printFlag = true
		case arg == "-clear" || arg == "--clear":
			if i+1 < len(args) {
				if sec, err := strconv.Atoi(args[i+1]); err == nil {
					clearSec = sec
					i++
				}
			}
		default:
			cleanArgs = append(cleanArgs, arg)
		}
	}

	if len(cleanArgs) == 0 {
		if err := app.InteractiveSearch(clearSec); err != nil {
			fmt.Fprintf(os.Stderr, "Search error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	targetPath := cleanArgs[0]
	field := ""
	if len(cleanArgs) >= 2 {
		field = cleanArgs[1]
	}

	if err := app.Retrieve(targetPath, field, printFlag, clearSec); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runGenerateCLI(app *VaultUseCase, args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	var (
		account  string
		title    string
		url      string
		length   int
		clearSec int
	)

	fs.StringVar(&account, "H", "", "Account identifier")
	fs.StringVar(&account, "a", "", "Account identifier")
	fs.StringVar(&title, "t", "", "Entry title")
	fs.StringVar(&url, "u", "", "Service URL")
	fs.IntVar(&length, "l", 24, "Password length")
	fs.IntVar(&clearSec, "clear", DefaultClearSec, "Auto-clear seconds")
	_ = fs.Parse(args)

	if len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: pas generate [-a account] [-t title] [-u url] <path>")
		os.Exit(1)
	}

	path := fs.Args()[0]
	if err := app.Generate(path, account, title, url, length, clearSec); err != nil {
		fmt.Fprintf(os.Stderr, "Generate error: %v\n", err)
		os.Exit(1)
	}
}

func runMoveCLI(app *VaultUseCase, args []string) {
	if len(args) < 2 {
		fmt.Fprintln(os.Stderr, "Usage: pas mv <source-path> <dest-path>")
		os.Exit(1)
	}
	if err := app.Move(args[0], args[1]); err != nil {
		fmt.Fprintf(os.Stderr, "Move error: %v\n", err)
		os.Exit(1)
	}
}

func runRemoveCLI(app *VaultUseCase, args []string) {
	fs := flag.NewFlagSet("rm", flag.ExitOnError)
	var recursive bool
	fs.BoolVar(&recursive, "r", false, "Remove path hierarchy recursively")
	fs.BoolVar(&recursive, "recursive", false, "Remove path hierarchy recursively")
	_ = fs.Parse(args)

	targets := fs.Args()
	if len(targets) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: pas rm [-r] <path>")
		os.Exit(1)
	}

	for _, t := range targets {
		if err := app.Remove(t, recursive); err != nil {
			fmt.Fprintf(os.Stderr, "Remove error on %s: %v\n", t, err)
			os.Exit(1)
		}
	}
}
