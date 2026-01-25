# Load .env file if it exists
ifneq (,$(wildcard .env))
    include .env
    # Only export specific variables that need to be in the environment
		export PROJECT_NAME
    export DB_HOST
		export DB_PORT
		export DB_NAME
		export DB_USER
		export DB_PASS
    # Add other variables that actually need to be in the environment
endif

# =============================================================================
#  Project Configuration
# =============================================================================
# Project Settings
PROJECT_NAME ?= myapp

DATABASE_URL = "postgres://$(DB_USER):$(DB_PASS)@$(DB_HOST):$(DB_PORT)/$(DB_NAME)?sslmode=disable"

GIT_PROJECT ?= $(shell git rev-parse --show-toplevel 2>/dev/null || echo "unknown")

# Directories
ROOT_DIR ?= $(shell pwd)
MIGRATIONS_DIR ?= $(ROOT_DIR)/migrations
PROJECT_DIR ?= $(ROOT_DIR)/cmd/$(PROJECT_NAME)

# Utils
GOOSE = "github.com/pressly/goose/v3/cmd/goose@latest"

# =============================================================================
# 🎨 Terminal Colors & Emoji
# =============================================================================
# Colors
BLUE := \033[34m
GREEN := \033[32m
YELLOW := \033[33m
RED := \033[31m
MAGENTA := \033[35m
CYAN := \033[36m
WHITE := \033[37m
BOLD := \033[1m
RESET := \033[0m\n

# Status Indicators
INFO := @printf "$(BLUE)ℹ️  %s$(RESET)"
SUCCESS := @printf "$(GREEN)✅ %s$(RESET)"
WARN := @printf "$(YELLOW)⚠️  %s$(RESET)"
ERROR := @printf "$(RED)❌ %s$(RESET)"
WORKING := @printf "$(CYAN)🔨 %s$(RESET)"
DEBUG := @printf "$(MAGENTA)🔍 %s$(RESET)"
ROCKET := @printf "$(GREEN)🚀 %s$(RESET)"
PACKAGE := @printf "$(CYAN)📦 %s$(RESET)"
TRASH := @printf "$(YELLOW)🗑️  %s$(RESET)"

# =============================================================================
# 🔄 Development Workflow
# =============================================================================
.PHONY: run
run: ## Run application
	$(ROCKET) "Running app..."
	go run $(PROJECT_DIR)

# =============================================================================
#  Database Operations
# =============================================================================
.PHONY: db-up
db-up: ## Run DB Docker container
	$(ROCKET) "Running DB Docker container..."
	docker compose -f "$(ROOT_DIR)/db.docker-compose.yaml" up -d

.PHONY: db-down
db-down: ## Remove DB Docker container
	$(TRASH) "Removing DB Docker container..."
	docker compose -f "$(ROOT_DIR)/db.docker-compose.yaml" down

.PHONY: add-migration
add-migration:  ## Adding database migration
ifndef NAME
	$(ERROR) "Usage: make add-migration NAME=migration_name"; exit 1
endif
	go run $(GOOSE) -dir $(MIGRATIONS_DIR) create $(NAME) sql

.PHONY: db-migrate
db-migrate: ## Run database migrations
	$(INFO) "Running database migrations..."
	@if [ -d "$(MIGRATIONS_DIR)" ]; then \
		go run $(GOOSE) -dir $(MIGRATIONS_DIR) postgres $(DATABASE_URL) up; \
	else \
		$(WARN) "No migrations directory found"; \
	fi

.PHONY: db-rollback
db-rollback: ## Rollback database migration
	$(INFO) "Rolling back database migration..."
	go run $(GOOSE) -dir $(MIGRATIONS_DIR) postgres $(DATABASE_URL) down

.PHONY: db-reset
db-reset: ## Reset database
	$(INFO) "Resetting database..."
	go run $(GOOSE) -dir $(MIGRATIONS_DIR) postgres $(DATABASE_URL) reset
