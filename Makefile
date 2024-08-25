.PHONY: lint check format test mypy

# Default target
all: lint check format mypy test

# Install dependencies
install:
	pip install -r requirements.txt
	pip install ruff pytest mypy

# Lint the code using ruff
lint:
	ruff check .

# Check the code without making changes
check:
	ruff check . --preview

# Format the code using ruff
format:
	ruff format .
	ruff check --fix-only .

# Run mypy for static type checking
mypy:
	mypy .

# Run tests
test:
	pytest tests/

# Clean up cache and temporary files
clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type f -name "*.py[co]" -delete
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
