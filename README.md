# cvec

A CLI tool for downloading, extracting, and searching CVE (Common Vulnerabilities and Exposures) data.

## Features

- **Database Management**: Fetch pre-built parquet files or build locally from JSON
- **Search**: Search CVEs by product, vendor, CWE ID, severity, and more
- **Get**: Retrieve detailed information about specific CVEs
- **Stats**: View database statistics

## Installation

```bash
# Using uv (recommended)
uv pip install .

# Or for development
uv pip install -e ".[dev]"
```

## Quick Start

```bash
# Download pre-built CVE database (recommended, fast!)
cvec db update

# Search for CVEs
cvec search "linux kernel"
cvec search --vendor "Microsoft" "Windows"
cvec search --severity critical
cvec search "CWE-79"

# Get details for a specific CVE
cvec get CVE-2024-1234

# Show database statistics
cvec stats
```

## Usage

### Database Management

The `db` subcommand manages the CVE database. The recommended approach is to use pre-built parquet files from the [cvec-db](https://github.com/RomainRiv/cvec-db) repository:

```bash
# Download latest pre-built database (recommended)
cvec db update

# Force update even if local is up-to-date
cvec db update --force

# Download specific version
cvec db update --tag v20260106

# Check database status
cvec db status
```

For advanced users who want to build the database locally:

```bash
# Download raw JSON files
cvec db download-json
cvec db download-json --years 5
cvec db download-json --all  # Include CAPEC/CWE

# Extract JSON to parquet
cvec db extract-parquet
cvec db extract-parquet --verbose
```

### Search

Search for CVEs using various criteria:

```bash
# Search by product name
cvec search "Apache HTTP Server"

# Search by vendor
cvec search --vendor "Apache" "HTTP Server"

# Search by CWE
cvec search "CWE-79"

# Filter by severity
cvec search "linux" --severity critical
cvec search "linux" --severity high

# Filter by date
cvec search "windows" --after 2024-01-01
cvec search "windows" --before 2024-06-01

# Filter by KEV (Known Exploited Vulnerabilities)
cvec search "windows" --kev

# Output formats
cvec search "linux" --format json
cvec search "linux" --format markdown
cvec search "linux" --format table  # default

# Save to file
cvec search "linux" --output results.json --format json

# Limit results
cvec search "linux" --limit 50
```

### Get

Get detailed information about a specific CVE:

```bash
cvec get CVE-2024-1234
cvec get CVE-2024-1234 --format json
cvec get CVE-2024-1234 --verbose
cvec get CVE-2024-1234 --output cve-details.json --format json
```

### Stats

Show database statistics:

```bash
cvec stats
cvec stats --format json
cvec stats --format markdown
```

### Recent

Show recently published CVEs:

```bash
cvec recent
cvec recent --days 7
cvec recent --limit 20
```

## Output Formats

- **table**: Human-readable table format (default)
- **json**: Machine-readable JSON format, ideal for LLM consumption
- **markdown**: Markdown format for documentation

## Configuration

Configuration can be set via environment variables:

- `CVE_DATA_DIR`: Directory for extracted data (default: `./data`)
- `CVE_DOWNLOAD_DIR`: Directory for downloaded files (default: `./download`)
- `CVE_DEFAULT_YEARS`: Number of years to download by default (default: 10)
- `CVEC_DB_REPO`: GitHub repository for pre-built parquet files (default: `RomainRiv/cvec-db`)

## Development

```bash
# Clone the repository
git clone https://github.com/RomainRiv/cvec.git
cd cvec

# Install dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Run with coverage
uv run pytest --cov=cvec
```

## License

MIT
