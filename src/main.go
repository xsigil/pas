package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// EpochZero defines the fixed time point used to sanitize all filesystem metadata.
var EpochZero = time.Unix(0, 0).UTC()

const (
	DirPermSecure   = 0700
	FilePermSecure  = 0600
	DefaultClearSec = 45
)

// init guarantees that under any execution flow, umask 0077 is permanently active.
func init() {
	syscall.Umask(0077)
}

// Entry represents the structured credential payload of encrypted .yaml.gpg files.
type Entry struct {
	Password  string            `yaml:"password"`
	Account   string            `yaml:"account,omitempty"`
	URL       string            `yaml:"url,omitempty"`
	OTP       string            `yaml:"otp,omitempty"`
	CreatedAt string            `yaml:"created_at,omitempty"`
	UpdatedAt string            `yaml:"updated_at,omitempty"`
	Comment   string            `yaml:"comment,omitempty"`
	Meta      map[string]string `yaml:"meta,omitempty"`
}

// ComputeAccountHash derives the 16-character SHA-256 identifier for anti-forensic filenames.
func ComputeAccountHash(account string) string {
	account = strings.TrimSpace(account)
	sum := sha256.Sum256([]byte(account))
	return hex.EncodeToString(sum[:])[:16]
}

type IndexItem struct {
	RelPath  string
	Account  string
	FullPath string
}

type CryptoService interface {
	Decrypt(path string) ([]byte, error)
	Encrypt(recipients []string, plaintext []byte, outputPath string) error
	GetRecipients(storeDir string) ([]string, error)
}

type ClipboardService interface {
	Copy(content string, clearSec int) error
}

type StoreRepository interface {
	ResolvePath(target string) (fullPath string, err error)
	ListAllYAMLFiles() ([]string, error)
	SecureWipe(path string) error
	SanitizeTimestamp(path string) error
	GetStoreDir() string
}

type GPGService struct{}

func NewGPGService() *GPGService {
	return &GPGService{}
}

func (g *GPGService) Decrypt(path string) ([]byte, error) {
	cmd := exec.Command("gpg", "--quiet", "--batch", "--decrypt", path)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("gpg decrypt error on %s: %s (%w)", filepath.Base(path), strings.TrimSpace(stderr.String()), err)
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
		return fmt.Errorf("gpg encrypt error: %s (%w)", strings.TrimSpace(stderr.String()), err)
	}
	return nil
}

func (g *GPGService) GetRecipients(storeDir string) ([]string, error) {
	idPath := filepath.Join(storeDir, ".gpg-id")
	data, err := os.ReadFile(idPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read .gpg-id: %w", err)
	}
	var recipients []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
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
		io.WriteString(stdin, content)
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

type FSStoreRepository struct {
	storeDir string
}

func NewFSStoreRepository() *FSStoreRepository {
	dir := os.Getenv("PASTORE_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: cannot resolve home directory: %v\n", err)
			os.Exit(1)
		}
		dir = filepath.Join(home, ".pastore")
	}
	_ = os.MkdirAll(dir, DirPermSecure)
	return &FSStoreRepository{storeDir: dir}
}

func (r *FSStoreRepository) GetStoreDir() string {
	return r.storeDir
}

func (r *FSStoreRepository) ResolvePath(target string) (string, error) {
	clean := strings.TrimSuffix(strings.TrimSuffix(target, ".yaml.gpg"), ".gpg")
	yamlPath := filepath.Join(r.storeDir, clean+".yaml.gpg")

	if _, err := os.Stat(yamlPath); err == nil {
		return yamlPath, nil
	}
	return "", fmt.Errorf("credential entry not found: %s", target)
}

func (r *FSStoreRepository) ListAllYAMLFiles() ([]string, error) {
	var files []string
	err := filepath.WalkDir(r.storeDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.Contains(path, "/.git/") {
			return nil
		}
		if strings.HasSuffix(path, ".yaml.gpg") {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func (r *FSStoreRepository) SanitizeTimestamp(path string) error {
	return os.Chtimes(path, EpochZero, EpochZero)
}

func (r *FSStoreRepository) SecureWipe(path string) error {
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	length := fi.Size()
	if length > 0 {
		f, err := os.OpenFile(path, os.O_WRONLY, 0600)
		if err == nil {
			noise := make([]byte, length)
			_, _ = rand.Read(noise)
			_, _ = f.Write(noise)
			_ = f.Sync()
			f.Close()
		}
	}
	return os.Remove(path)
}

type CredentialUseCase struct {
	repo      StoreRepository
	crypto    CryptoService
	clipboard ClipboardService
}

func NewCredentialUseCase(repo StoreRepository, crypto CryptoService, clip ClipboardService) *CredentialUseCase {
	return &CredentialUseCase{repo: repo, crypto: crypto, clipboard: clip}
}

func (uc *CredentialUseCase) Retrieve(target, key string, printOnly bool, clearSec int) error {
	fullPath, err := uc.repo.ResolvePath(target)
	if err != nil {
		return err
	}

	data, err := uc.crypto.Decrypt(fullPath)
	if err != nil {
		return err
	}

	if printOnly && key == "" {
		fmt.Print(string(data))
		return nil
	}

	targetKey := "password"
	if key != "" {
		targetKey = strings.ToLower(key)
	}

	var dict map[string]any
	if err := yaml.Unmarshal(data, &dict); err != nil {
		return fmt.Errorf("malformed YAML in entry: %w", err)
	}

	normalized := make(map[string]any)
	for k, v := range dict {
		normalized[strings.ToLower(k)] = v
	}

	val, found := normalized[targetKey]
	if !found {
		return fmt.Errorf("key '%s' not present in entry", targetKey)
	}

	payload := fmt.Sprintf("%v", val)
	if printOnly {
		fmt.Println(payload)
		return nil
	}

	if err := uc.clipboard.Copy(payload, clearSec); err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Copied key '%s' to clipboard (clears in %ds).\n", targetKey, clearSec)
	return nil
}

func (uc *CredentialUseCase) InteractiveSearch(clearSec int) error {
	files, err := uc.repo.ListAllYAMLFiles()
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return errors.New("pastore repository is currently empty")
	}

	numWorkers := runtime.NumCPU() * 2
	jobs := make(chan string, len(files))
	results := make(chan IndexItem, len(files))
	var wg sync.WaitGroup

	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for path := range jobs {
				results <- uc.decryptMetadataWorker(path)
			}
		}()
	}

	for _, f := range files {
		jobs <- f
	}
	close(jobs)

	wg.Wait()
	close(results)

	var items []IndexItem
	itemMap := make(map[string]IndexItem)
	var displayLines []string

	for item := range results {
		items = append(items, item)
		display := fmt.Sprintf("%-50s  │  %s", item.RelPath, item.Account)
		displayLines = append(displayLines, display)
		itemMap[display] = item
	}

	selectedDisplay, action, err := uc.runFzfUI(displayLines)
	if err != nil {
		return nil // Clean cancellation
	}

	chosen, exists := itemMap[selectedDisplay]
	if !exists {
		return errors.New("selected item not found in index")
	}

	keyToFetch := "password"
	if action == "ctrl-y" {
		keyToFetch = "account"
	} else if action == "ctrl-o" {
		keyToFetch = "otp"
	}

	return uc.Retrieve(chosen.RelPath, keyToFetch, false, clearSec)
}

func (uc *CredentialUseCase) decryptMetadataWorker(fullPath string) IndexItem {
	storeDir := uc.repo.GetStoreDir()
	rel, _ := filepath.Rel(storeDir, fullPath)
	cleanRel := strings.TrimSuffix(rel, ".yaml.gpg")

	raw, err := uc.crypto.Decrypt(fullPath)
	if err != nil {
		return IndexItem{RelPath: cleanRel, Account: "(locked/undecryptable)", FullPath: fullPath}
	}

	account := ""
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err == nil {
		for k, v := range doc {
			lk := strings.ToLower(k)
			if lk == "account" || lk == "email" || lk == "user" {
				account = fmt.Sprintf("%v", v)
				break
			}
		}
	}

	return IndexItem{
		RelPath:  cleanRel,
		Account:  account,
		FullPath: fullPath,
	}
}

func (uc *CredentialUseCase) runFzfUI(lines []string) (string, string, error) {
	cmd := exec.Command("fzf",
		"--height=40%",
		"--reverse",
		"--prompt=pas > ",
		"--header=Enter: copy password | Ctrl-Y: copy account | Ctrl-O: copy otp",
		"--expect=ctrl-y,ctrl-o",
	)
	cmd.Stdin = strings.NewReader(strings.Join(lines, "\n"))
	cmd.Stderr = os.Stderr

	var stdout bytes.Buffer
	cmd.Stdout = &stdout

	if err := cmd.Run(); err != nil {
		return "", "", err
	}

	raw := strings.TrimRight(stdout.String(), "\r\n")
	outLines := strings.Split(raw, "\n")
	if len(outLines) < 2 {
		return "", "", errors.New("empty selection")
	}

	return outLines[1], outLines[0], nil
}

func (uc *CredentialUseCase) Generate(account, dirPath string, length int, clearSec int) error {
	if length <= 0 {
		length = 24
	}
	password, err := generateCryptographicPassword(length)
	if err != nil {
		return err
	}

	hashName := ComputeAccountHash(account)
	targetDir := filepath.Join(uc.repo.GetStoreDir(), dirPath)
	if err := os.MkdirAll(targetDir, DirPermSecure); err != nil {
		return fmt.Errorf("failed to create directory tree: %w", err)
	}

	destGPGPath := filepath.Join(targetDir, hashName+".yaml.gpg")
	nowUTC := time.Now().UTC().Format(time.RFC3339)

	entry := Entry{
		Password:  password,
		Account:   account,
		CreatedAt: nowUTC,
		UpdatedAt: nowUTC,
	}

	yamlPayload, err := yaml.Marshal(&entry)
	if err != nil {
		return err
	}

	recipients, err := uc.crypto.GetRecipients(uc.repo.GetStoreDir())
	if err != nil {
		return err
	}

	if err := uc.crypto.Encrypt(recipients, yamlPayload, destGPGPath); err != nil {
		return err
	}

	_ = os.Chmod(destGPGPath, FilePermSecure)
	_ = uc.repo.SanitizeTimestamp(destGPGPath)

	if err := uc.clipboard.Copy(password, clearSec); err != nil {
		return err
	}

	relDest, _ := filepath.Rel(uc.repo.GetStoreDir(), destGPGPath)
	fmt.Fprintf(os.Stderr, "Created: %s\n", relDest)
	fmt.Fprintf(os.Stderr, "Copied generated password to clipboard (clears in %ds).\n", clearSec)
	return nil
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

func (uc *CredentialUseCase) Migrate(fromDir string, dryRun bool) error {
	sourceDir := fromDir
	if sourceDir == "" {
		home, _ := os.UserHomeDir()
		sourceDir = filepath.Join(home, ".password-store")
	}

	var legacyFiles []string
	filepath.WalkDir(sourceDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || strings.Contains(path, "/.git/") {
			return nil
		}
		if strings.HasSuffix(path, ".gpg") && !strings.HasSuffix(path, ".yaml.gpg") {
			legacyFiles = append(legacyFiles, path)
		}
		return nil
	})

	if len(legacyFiles) == 0 {
		fmt.Fprintln(os.Stderr, "No legacy .gpg entries discovered.")
		return nil
	}

	recipients, err := uc.crypto.GetRecipients(sourceDir)
	if err != nil {
		recipients, err = uc.crypto.GetRecipients(uc.repo.GetStoreDir())
		if err != nil {
			return fmt.Errorf("unable to determine recipients: %w", err)
		}
	}

	fmt.Fprintf(os.Stderr, "Discovered %d legacy entry/entries to convert into pure YAML.\n", len(legacyFiles))

	for _, oldPath := range legacyFiles {
		raw, err := uc.crypto.Decrypt(oldPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Skipping (decrypt failed): %s\n", oldPath)
			continue
		}

		lines := strings.Split(strings.TrimRight(string(raw), "\r\n"), "\n")
		var pass, acc, comment string
		if len(lines) >= 1 {
			pass = lines[0]
		}
		if len(lines) >= 2 {
			acc = lines[1]
		}
		if len(lines) >= 3 {
			comment = strings.Join(lines[2:], "\n")
		}

		relPath, _ := filepath.Rel(sourceDir, oldPath)
		relDir := filepath.Dir(relPath)
		baseName := strings.TrimSuffix(filepath.Base(oldPath), ".gpg")

		var newFileName string
		if acc != "" {
			newFileName = ComputeAccountHash(acc) + ".yaml.gpg"
		} else {
			newFileName = baseName + ".yaml.gpg"
		}

		destPath := filepath.Join(uc.repo.GetStoreDir(), relDir, newFileName)

		if dryRun {
			fmt.Printf("[DRY-RUN] %s -> %s\n", relPath, filepath.Join(relDir, newFileName))
			continue
		}

		_ = os.MkdirAll(filepath.Dir(destPath), DirPermSecure)

		entry := Entry{
			Password:  pass,
			Account:   acc,
			Comment:   comment,
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
		}

		yamlBytes, _ := yaml.Marshal(&entry)
		if err := uc.crypto.Encrypt(recipients, yamlBytes, destPath); err != nil {
			fmt.Fprintf(os.Stderr, "Failed encrypting %s: %v\n", destPath, err)
			continue
		}

		_ = os.Chmod(destPath, FilePermSecure)
		_ = uc.repo.SanitizeTimestamp(destPath)
		_ = uc.repo.SecureWipe(oldPath)
		fmt.Printf("Migrated: %s -> %s\n", relPath, newFileName)
	}

	return nil
}

func (uc *CredentialUseCase) Audit() error {
	storeDir := uc.repo.GetStoreDir()
	fmt.Fprintf(os.Stderr, "==> Auditing %s for permissions and epoch timestamps...\n", storeDir)

	count := 0
	fixedPerms := 0
	fixedTimes := 0

	err := filepath.Walk(storeDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || strings.Contains(path, "/.git/") {
			return nil
		}
		count++
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
				_ = uc.repo.SanitizeTimestamp(path)
				fixedTimes++
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "Audit complete. Scanned %d node(s).\n", count)
	fmt.Fprintf(os.Stderr, "Permissions normalized (0700/0600): %d\n", fixedPerms)
	fmt.Fprintf(os.Stderr, "Timestamps reset to EpochZero (1970-01-01): %d\n", fixedTimes)
	return nil
}

var version = "1.0.0"

func main() {
	repo := NewFSStoreRepository()
	crypto := NewGPGService()
	clip := NewWaylandClipboardService()
	app := NewCredentialUseCase(repo, crypto, clip)

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "generate":
			runGenerateCLI(app, os.Args[2:])
			return
		case "migrate":
			runMigrateCLI(app, os.Args[2:])
			return
		case "audit":
			if err := app.Audit(); err != nil {
				fmt.Fprintf(os.Stderr, "Audit failed: %v\n", err)
				os.Exit(1)
			}
			return
		case "version", "--version":
			fmt.Printf("pas v%s (Arch Linux / Wayland Native)\n", version)
			return
		}
	}

	runDefaultCLI(app, os.Args[1:])
}

func runDefaultCLI(app *CredentialUseCase, args []string) {
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

	// 0 positional args -> interactive fzf search
	if len(cleanArgs) == 0 {
		if err := app.InteractiveSearch(clearSec); err != nil {
			fmt.Fprintf(os.Stderr, "Search error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	target := cleanArgs[0]
	key := ""
	if len(cleanArgs) >= 2 {
		key = cleanArgs[1]
	}

	if err := app.Retrieve(target, key, printFlag, clearSec); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func runGenerateCLI(app *CredentialUseCase, args []string) {
	fs := flag.NewFlagSet("generate", flag.ExitOnError)
	var (
		hashAcc  string
		length   int
		clearSec int
	)

	fs.StringVar(&hashAcc, "H", "", "Account identifier to hash into filename")
	fs.IntVar(&length, "l", 24, "Generated password length")
	fs.IntVar(&clearSec, "clear", DefaultClearSec, "Seconds before clipboard auto-clears")
	_ = fs.Parse(args)

	if hashAcc == "" || len(fs.Args()) == 0 {
		fmt.Fprintln(os.Stderr, "Usage: pas generate -H <account/email> <directory-path>")
		os.Exit(1)
	}

	dirPath := fs.Args()[0]
	if err := app.Generate(hashAcc, dirPath, length, clearSec); err != nil {
		fmt.Fprintf(os.Stderr, "Generation error: %v\n", err)
		os.Exit(1)
	}
}

func runMigrateCLI(app *CredentialUseCase, args []string) {
	fs := flag.NewFlagSet("migrate", flag.ExitOnError)
	var (
		fromDir string
		dryRun  bool
	)

	fs.StringVar(&fromDir, "from", "", "Source password-store directory (defaults to ~/.password-store)")
	fs.BoolVar(&dryRun, "dry-run", false, "Preview filename mappings without changing disk state")
	_ = fs.Parse(args)

	if err := app.Migrate(fromDir, dryRun); err != nil {
		fmt.Fprintf(os.Stderr, "Migration error: %v\n", err)
		os.Exit(1)
	}
}