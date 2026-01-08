# Justfile for cvec project
# Run 'just --list' to see all available recipes

# Default recipe (runs when you just type 'just')
default:
    @just --list

# Install the package in development mode with dev dependencies
install:
    uv pip install -e ".[dev]"

# Install all dependencies
sync:
    uv sync --all-extras

# Run tests with pytest
test:
    uv run pytest tests/ -v

# Run tests with coverage report
test-cov:
    uv run pytest tests/ -v --cov=src/cvec --cov-report=term-missing --cov-report=html

# Format code with Black
format:
    uv run black src/ tests/

# Check code formatting without making changes
format-check:
    uv run black --check src/ tests/

# Run type checking with mypy
typecheck:
    uv run mypy src/cvec

# Run all checks (format check and type check)
check: format-check typecheck

# Build the package
build:
    uv build

# Clean build artifacts and cache files
clean:
    rm -rf build/
    rm -rf dist/
    rm -rf src/*.egg-info
    rm -rf .pytest_cache
    rm -rf htmlcov
    rm -rf .coverage
    find . -type d -name __pycache__ -exec rm -rf {} +
    find . -type f -name "*.pyc" -delete

# Run the CLI (example usage)
run *ARGS:
    uv run cvec {{ARGS}}

# Full CI pipeline (format, check, test)
ci: format-check typecheck test

# Prepare for release (format, check, test, build)
release: format check test build
    @echo "Package ready for release in dist/"
