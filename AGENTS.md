# AGENTS.md

This document provides essential information for AI agents working in the cvec repository.

## Project Overview

**cvec** is a CLI tool for downloading, extracting, and searching CVE (Common Vulnerabilities and Exposures) data. It's a Python package that provides both a command-line interface and a library for working with CVE data in parquet format.

- **Language**: Python 3.10+ (currently uses 3.12)
- **Package Manager**: uv (modern, fast Python package manager)
- **Task Runner**: just (command runner with Justfile)
- **Testing**: pytest with coverage
- **Code Quality**: Black (formatting), mypy (type checking)
- **Data Format**: Polars DataFrames stored as Parquet files

## Project Structure

```
cvec/
├── src/cvec/              # Source code
│   ├── cli/              # CLI commands (Typer-based)
│   ├── core/             # Configuration management
│   ├── models/           # Pydantic data models
│   └── services/         # Business logic (downloader, search, etc.)
├── tests/                # Test suite
├── data/                 # CVE database (parquet files)
├── download/             # Downloaded raw JSON files
├── pyproject.toml        # Project configuration
├── justfile              # Task definitions
└── uv.lock              # Locked dependencies
```

## Using uv

**uv** is the package manager used throughout this project. It's fast and modern, replacing traditional pip workflows.

### Key uv Commands

```bash
# Install Python version (uv manages Python installations)
uv python install 3.12

# Sync dependencies from pyproject.toml (recommended for dev setup)
uv sync --all-extras

# Install package in editable mode with dev dependencies
uv pip install -e ".[dev]"

# Install with semantic search support
uv pip install ".[semantic]"

# Run commands in the uv-managed environment
uv run pytest
uv run cvec search "linux"
uv run black src/
```

### Important uv Notes

1. **Don't use bare `python` or `pip`**: Always prefix with `uv run` to ensure you're using the project environment
2. **uv.lock file**: This is the lockfile - commit it to ensure reproducible builds
3. **pyproject.toml**: Single source of truth for dependencies
4. **Python version**: Specified in `.python-version` (3.12)

## Using the Justfile

The `justfile` provides convenient shortcuts for common tasks. Run `just --list` to see all available commands.

### Essential Just Commands

```bash
# List all available commands
just --list

# Install dependencies (development setup)
just sync                  # Recommended: uv sync --all-extras
just install               # Alternative: uv pip install -e ".[dev]"

# Testing
just test                  # Run tests with pytest
just test-cov             # Run tests with coverage report (generates htmlcov/)

# Code Quality
just format               # Format code with Black
just format-check         # Check formatting without changes
just typecheck            # Run mypy type checking
just check                # Run format-check + typecheck

# Running the CLI
just run <args>           # Example: just run search "linux"

# CI Pipeline
just ci                   # Run format-check, typecheck, and test
just release              # Full pipeline: format, check, test, build

# Cleanup
just clean                # Remove build artifacts, cache files, etc.

# Building
just build                # Build package (creates dist/)
```

### Justfile Workflow Pattern

The justfile uses `uv run` for all commands, ensuring consistency. When adding new just recipes, always use `uv run <command>` pattern.

## Testing

### Test Framework

- **Framework**: pytest
- **Coverage**: pytest-cov
- **Location**: `tests/` directory
- **Fixtures**: Defined in `tests/conftest.py` (725 lines of comprehensive fixtures)

### Running Tests

```bash
# Basic test run
just test
# or
uv run pytest tests/ -v

# With coverage report
just test-cov
# or
uv run pytest tests/ -v --cov=src/cvec --cov-report=term-missing --cov-report=html

# Run specific test file
uv run pytest tests/test_search.py -v

# Run specific test
uv run pytest tests/test_search.py::TestSeverityThresholds::test_severity_levels_exist -v
```

### Test Configuration

From `pyproject.toml`:
```toml
[tool.pytest.ini_options]
testpaths = ["tests"]
python_files = ["test_*.py"]
python_classes = ["Test*"]
python_functions = ["test_*"]
addopts = "-v --tb=short"
```

### Test Structure

- Tests follow standard pytest conventions
- Extensive fixtures in `conftest.py` provide sample CVE data
- Tests cover all services: downloader, extractor, search, embeddings, artifact_fetcher
- Integration tests in `test_integration.py`
- Tests use sample CVE data (real-world examples like CVE-2022-2196)

### Coverage Reports

Coverage reports are generated in `htmlcov/` directory. Open `htmlcov/index.html` in a browser to view detailed coverage.

## Code Quality

### Black Formatting

```bash
# Format all code
just format

# Check without modifying
just format-check
```

**Configuration** (from `pyproject.toml`):
- Line length: 88
- Target versions: Python 3.10, 3.11, 3.12
- Excludes: `.venv`, `build`, `dist`, `cve_model.py`

### Type Checking with mypy

```bash
just typecheck
```

**Configuration**:
- Python version: 3.10
- `disallow_untyped_defs`: false (not strictly enforced)
- `ignore_missing_imports`: true

## Dependencies

### Core Dependencies
- **polars** (>=1.31.0): Fast DataFrame library (alternative to pandas)
- **pydantic** (>=2.11.7): Data validation and models
- **requests** (>=2.32.3): HTTP library
- **typer** (>=0.16.0): CLI framework
- **rich** (>=14.0.0): Terminal formatting
- **numpy** (>=2.0.0): Numerical operations
- **fastembed** (>=0.5.0): Embeddings for semantic search

### Optional Dependencies

```toml
[project.optional-dependencies]
semantic = ["fastembed>=0.5.0"]  # For semantic search
dev = ["pytest>=8.0.0", "pytest-cov>=4.1.0", "types-requests", "black", "mypy", ...]
```

## CLI Usage

The CLI is built with Typer and has two main command groups:

### Database Management (`cvec db`)

```bash
# For regular users:
cvec db update              # Download pre-built parquet files (recommended)
cvec db status              # Show database status

# For advanced users / CI (cvec db build):
cvec db build download-json        # Download raw JSON files
cvec db build extract-parquet      # Convert JSON to parquet
cvec db build extract-embeddings   # Generate embeddings for semantic search
cvec db build create-manifest      # Create manifest.json for distribution
```

### Search & Query

```bash
cvec search "linux kernel"                    # Basic search
cvec search --vendor "Microsoft" "Windows"    # Vendor filter
cvec search --severity critical               # Severity filter
cvec search --semantic "memory corruption"    # Semantic search (requires semantic extras)
cvec get CVE-2024-1234                       # Get specific CVE
cvec stats                                    # Database statistics
```

## Data Storage

### Directory Structure

- `data/`: CVE database (parquet files)
  - `cves.parquet`: Main CVE records
  - `cve_descriptions.parquet`: Descriptions
  - `cve_metrics.parquet`: CVSS metrics
  - `cve_products.parquet`: Affected products
  - `cve_cwes.parquet`: CWE mappings
  - etc.
- `download/`: Raw downloaded files
  - `cve_github/`: JSON files from GitHub
  - `capec/`: CAPEC XML
  - `cwe/`: CWE XML

### Configuration

Configuration is managed by `Config` class in `src/cvec/core/config.py`:
- Defaults to project-relative paths (`data/`, `download/`)
- Can be overridden with environment variables:
  - `CVE_DATA_DIR`: Data directory
  - `CVE_DOWNLOAD_DIR`: Download directory
  - `CVE_DEFAULT_YEARS`: Years to download (default: 10)
- Can be overridden per-command with `--data-dir` parameter:
  - `cvec db update --data-dir /path/to/data`
  - `cvec db status --data-dir /path/to/data`
  - `cvec db build download-json --data-dir /path/to/data`
  - `cvec db build extract-parquet --data-dir /path/to/data`
  - `cvec db build extract-embeddings --data-dir /path/to/data`
  - `cvec db build create-manifest --data-dir /path/to/data`

## CI/CD

### GitHub Actions Workflow

The project uses GitHub Actions for CI (`.github/workflows/ci.yml`):

**Test Matrix**:
- OS: Ubuntu, macOS, Windows
- Python: 3.12, 3.13

**CI Steps**:
1. Install uv
2. Set up Python
3. Install just
4. Sync dependencies (`uv sync --all-extras`)
5. Run format check
6. Run type checking (continue-on-error)
7. Run tests with coverage

**Build Step**:
- Runs after tests pass
- Builds package with `just build`
- Uploads artifacts

### Running CI Locally

```bash
# Run the full CI pipeline locally
just ci

# Step by step
just format-check
just typecheck
just test
```

## Common Development Tasks

### Setting Up Development Environment

```bash
# 1. Clone repository
git clone <repo-url>
cd cvec

# 2. Ensure uv is installed
# See: https://docs.astral.sh/uv/

# 3. Sync all dependencies
just sync
# or
uv sync --all-extras

# 4. Verify installation
uv run cvec --help
```

### Making Changes

```bash
# 1. Create/edit code in src/cvec/

# 2. Format code
just format

# 3. Run tests
just test

# 4. Check types (optional, has errors)
just typecheck

# 5. Run full CI pipeline
just ci
```

### Adding Dependencies

```bash
# Edit pyproject.toml, then:
uv sync

# Or use uv to add directly:
uv add <package-name>

# For dev dependencies:
uv add --dev <package-name>
```

### Building and Distribution

```bash
# Build package
just build

# Output will be in dist/
# - dist/cvec-0.1.0-py3-none-any.whl
# - dist/cvec-0.1.0.tar.gz
```

## Key Services

### DownloadService (`src/cvec/services/downloader.py`)
- Downloads raw CVE JSON files from GitHub
- Supports year-based filtering
- Handles CAPEC/CWE downloads

### ExtractorService (`src/cvec/services/extractor.py`)
- Converts JSON files to normalized Parquet format
- Creates multiple related tables (products, metrics, descriptions, etc.)
- Uses Polars for efficient processing

### CVESearchService (`src/cvec/services/search.py`)
- Searches across multiple dimensions (product, vendor, CWE, severity)
- Supports semantic search with embeddings
- Returns SearchResult objects with rich filtering

### EmbeddingsService (`src/cvec/services/embeddings.py`)
- Generates embeddings for semantic search
- Optional dependency (fastembed)
- Creates `cve_embeddings.parquet`

### ArtifactFetcher (`src/cvec/services/artifact_fetcher.py`)
- Fetches pre-built database files from GitHub releases
- Validates checksums
- Checks schema version compatibility

## Important Notes

1. **Use uv, not pip**: This project is designed for uv. Don't use `pip` directly.

2. **Use just for commands**: The justfile provides the standard interface. Use `just <command>` rather than remembering long uv commands.

3. **Test data location**: Tests use fixtures from `conftest.py` with temporary directories. They don't modify the actual `data/` directory.

4. **Semantic search is optional**: The `fastembed` dependency is large (~500MB). It's only needed for semantic search features.

5. **Data format is Polars**: The project uses Polars DataFrames, not pandas. They're similar but Polars is faster and has different APIs.

6. **Multiple parquet files**: The database is normalized across multiple parquet files (cves, products, metrics, etc.). This is intentional for efficient querying.

7. **CVE Model exclusion**: `src/cvec/models/cve_model.py` is excluded from Black formatting (it's auto-generated).

8. **Type checking has errors**: `just typecheck` may show errors. It's set to `continue-on-error` in CI.

## Troubleshooting

### "Module not found" errors
```bash
# Ensure dependencies are synced
just sync
```

### Tests failing locally but not in CI
```bash
# Make sure you're using the right Python version
uv python install 3.12
uv sync --all-extras
```

### Clean build issues
```bash
# Clean all artifacts and rebuild
just clean
just sync
```

### Semantic search not working
```bash
# Install semantic extras
uv pip install -e ".[semantic]"
# Generate embeddings
just embeddings
```

## Resources

- **uv documentation**: https://docs.astral.sh/uv/
- **just documentation**: https://just.systems/man/en/
- **Polars documentation**: https://pola.rs/
- **Typer documentation**: https://typer.tiangolo.com/
- **CVE Database**: https://github.com/RomainRiv/cvec-db

## Quick Reference

```bash
# Setup
just sync

# Development cycle
just format && just test

# Full check before commit
just ci

# Run CLI
just run search "linux"

# Clean everything
just clean
```
