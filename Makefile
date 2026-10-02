# STREAMING_CHUNK:Defining build configuration and metadata...
APP_NAME := pas
BUILD_DIR := build
SRC := src/main.go
PREFIX ?= /usr/local
INSTALL_BIN := $(PREFIX)/bin

GO := go
GOFLAGS := -trimpath -ldflags="-s -w -X main.version=1.0.0"

.PHONY: all build clean clear install uninstall test fmt setup tidy

all: build

# STREAMING_CHUNK:Configuring GitHub repo creation and module initialization...
setup:
	@echo "==> Verifying GitHub CLI (gh) installation and authentication..."
	@if ! command -v gh >/dev/null 2>&1; then \
		echo "Error: gh (GitHub CLI) is not installed. Please install it with 'sudo pacman -S github-cli'."; \
		exit 1; \
	fi
	@GH_USER=$$(gh api user -q .login 2>/dev/null); \
	if [ -z "$$GH_USER" ]; then \
		echo "Error: gh authentication required. Run 'gh auth login' first."; \
		exit 1; \
	fi; \
	echo "==> Authenticated as GitHub user: $$GH_USER"; \
	if ! gh repo view "$$GH_USER/$(APP_NAME)" >/dev/null 2>&1; then \
		echo "==> Creating public GitHub repository '$$GH_USER/$(APP_NAME)' via gh..."; \
		gh repo create $(APP_NAME) --public --source=. --remote=origin --push || true; \
	else \
		echo "==> GitHub repository '$$GH_USER/$(APP_NAME)' already exists."; \
	fi; \
	MODULE_NAME="github.com/$$GH_USER/$(APP_NAME)"; \
	if [ ! -f go.mod ]; then \
		echo "==> Initializing Go module: $$MODULE_NAME"; \
		$(GO) mod init "$$MODULE_NAME"; \
	fi
	@echo "==> Ensuring src/ directory structure..."
	@mkdir -p src
	@if [ -f main.go ] && [ ! -f $(SRC) ]; then \
		echo "==> Relocating ./main.go to $(SRC)..."; \
		mv main.go $(SRC); \
	fi
	@echo "==> Fetching required Go dependencies (gopkg.in/yaml.v3)..."
	$(GO) get gopkg.in/yaml.v3
	$(GO) mod tidy
	@echo "==> Setup complete. Repository and dependencies configured."

# STREAMING_CHUNK:Configuring compile targets and dependency checks...
build:
	@if [ ! -f go.mod ]; then \
		echo "==> go.mod not detected. Automatically running 'make setup'..."; \
		$(MAKE) setup; \
	fi
	@mkdir -p src $(BUILD_DIR)
	@if [ -f main.go ] && [ ! -f $(SRC) ]; then \
		echo "==> Moving root main.go into $(SRC)..."; \
		mv main.go $(SRC); \
	fi
	@if [ ! -f $(SRC) ]; then \
		echo "Error: Source file $(SRC) not found."; \
		exit 1; \
	fi
	@echo "==> Building $(APP_NAME) (Go native from $(SRC) -> $(BUILD_DIR)/$(APP_NAME))..."
	$(GO) build $(GOFLAGS) -o $(BUILD_DIR)/$(APP_NAME) $(SRC)
	@chmod 755 $(BUILD_DIR)/$(APP_NAME)
	@echo "==> Successfully built $(BUILD_DIR)/$(APP_NAME)"

# STREAMING_CHUNK:Configuring installation and system deployment...
install: build
	@echo "==> Installing $(APP_NAME) to $(INSTALL_BIN)..."
	@install -d $(INSTALL_BIN)
	@install -m 755 $(BUILD_DIR)/$(APP_NAME) $(INSTALL_BIN)/$(APP_NAME)
	@echo "==> Installed: $(INSTALL_BIN)/$(APP_NAME)"

uninstall:
	@echo "==> Removing $(INSTALL_BIN)/$(APP_NAME)..."
	@rm -f $(INSTALL_BIN)/$(APP_NAME)
	@echo "==> Uninstalled."

# STREAMING_CHUNK:Configuring maintenance and cleanup targets...
clean:
	@echo "==> Cleaning build artifacts..."
	@rm -rf $(BUILD_DIR)

clear: clean

tidy:
	@echo "==> Tidying Go module dependencies..."
	$(GO) mod tidy

fmt:
	@echo "==> Formatting Go source code..."
	$(GO) fmt ./...

test:
	@echo "==> Running Go test suite..."
	$(GO) test -v -race ./...