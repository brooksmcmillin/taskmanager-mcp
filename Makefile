.PHONY: help install install-dev test lint format security clean docker-build docker-up docker-down

help:  ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

install:  ## Install production dependencies
	pip install -r requirements.txt

install-dev:  ## Install development dependencies
	pip install -r requirements.txt
	pip install black ruff isort mypy types-requests pytest pytest-cov pre-commit
	pip install pip-audit safety bandit pip-licenses
	pre-commit install

test:  ## Run tests
	pytest tests/ -v --tb=short

test-cov:  ## Run tests with coverage
	pytest tests/ -v --cov=. --cov-report=html --cov-report=term

lint:  ## Run all linting checks
	@echo "Running Black..."
	black --check *.py
	@echo "Running isort..."
	isort --check-only *.py
	@echo "Running Ruff..."
	ruff check *.py
	@echo "Running mypy..."
	mypy --config-file mypy.ini *.py

format:  ## Auto-format code
	black *.py
	isort *.py
	ruff check --fix *.py

security:  ## Run security checks
	@echo "Running pip-audit..."
	pip-audit
	@echo "Running safety..."
	safety check
	@echo "Running bandit..."
	bandit -r . -f json -o bandit-report.json --exclude ./tests,./venv,./.venv || true
	bandit -r . --exclude ./tests,./venv,./.venv
	@echo "Checking for secrets..."
	@grep -r -E "password.*=.*['\"][^'\"]{8,}['\"]" --exclude-dir=venv --exclude-dir=.venv --exclude-dir=node_modules --exclude-dir=.git --exclude="*.pyc" . || echo "No hardcoded passwords found"

pre-commit:  ## Run pre-commit hooks on all files
	pre-commit run --all-files

docker-build:  ## Build Docker images
	docker compose build

docker-up:  ## Start Docker containers
	docker compose up -d

docker-down:  ## Stop Docker containers
	docker compose down

docker-logs:  ## Show Docker logs
	docker compose logs -f

docker-restart:  ## Restart Docker containers
	docker compose restart

clean:  ## Clean up generated files
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	find . -type f -name "*.coverage" -delete
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".mypy_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".ruff_cache" -exec rm -rf {} + 2>/dev/null || true
	rm -rf htmlcov/
	rm -f bandit-report.json
	rm -f pip-audit.json
	rm -f safety-report.json

all: clean install-dev lint test security  ## Run all checks
