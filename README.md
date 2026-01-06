# cvec

A CLI tool for downloading, extracting, and searching CVE (Common Vulnerabilities and Exposures) data.

## Features

- **Download**: Fetch CVE data from the official [cvelistV5 repository](https://github.com/CVEProject/cvelistV5)
- **Extract**: Convert JSON CVE data to efficient Parquet format for fast querying
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
# Download CVE data (last 10 years by default)
cvec download

# Extract to Parquet format
cvec extract

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

### Download

Download CVE data from the cvelistV5 repository:

```bash
# Download last 10 years (default)
cvec download

# Download specific number of years
cvec download --years 5

# Download only CVEs (skip CAPEC/CWE)
cvec download --cves

# Download all data (CVEs, CWEs, CAPECs)
cvec download --all
```

### Extract

Extract CVE data from JSON files to Parquet format:

```bash
cvec extract
cvec extract --years 5
cvec extract --verbose
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

## Development

```bash
# Clone the repository
git clone https://github.com/yourusername/cvec.git
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
