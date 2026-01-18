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

# With semantic search support (optional, adds ~500MB dependencies)
uv pip install ".[semantic]"

# For development (includes all features)
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

# Semantic search (natural language) - requires: pip install cvec[semantic]
cvec search --semantic "memory corruption in image parsing"
cvec search --semantic "authentication bypass in web applications"

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
cvec db build download-json
cvec db build download-json --years 5
cvec db build download-json --all  # Include CAPEC/CWE

# Extract JSON to parquet
cvec db build extract-parquet
cvec db build extract-parquet --verbose

# Generate embeddings for semantic search
cvec db build extract-embeddings
cvec db build extract-embeddings --batch-size 512
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

# Filter by CVSS score range
cvec search "linux" --cvss-min 7.0
cvec search "linux" --cvss-min 9.0 --cvss-max 10.0

# Filter by CWE
cvec search --cwe 787                    # CWE-787 (Out-of-bounds Write)
cvec search "linux" --cwe 416            # Combined with query

# Filter by date
cvec search "windows" --after 2024-01-01
cvec search "windows" --before 2024-06-01

# Filter by KEV (Known Exploited Vulnerabilities)
cvec search "windows" --kev

# Search by Package URL (PURL) - new in CVE schema 5.2
cvec search --purl "pkg:pypi/django"
cvec search --purl "pkg:npm/lodash"
cvec search --purl "pkg:maven/org.apache.xmlgraphics/batik-anim"
cvec search --purl "pkg:github/package-url/purl-spec"

# Sort results
cvec search "linux" --sort date          # Sort by date (descending by default)
cvec search "linux" --sort date --order ascending   # Sort by date, oldest first
cvec search "linux" --sort cvss          # Sort by CVSS (highest first)
cvec search "linux" --sort severity --order ascending  # Sort by severity, lowest first

# Output formats
cvec search "linux" --format json
cvec search "linux" --format markdown
cvec search "linux" --format table       # default

# Scripting: output only CVE IDs (one per line)
cvec search "linux" --ids-only
cvec search "linux" --ids-only | xargs -I {} cvec get {}
cvec search "linux" --ids-only | xargs -I {} cvec get {}

# Save to file
cvec search "linux" --output results.json --format json

# Limit results
cvec search "linux" --limit 50
```

### Semantic Search

Semantic search uses natural language to find CVEs with similar meaning, even if the exact words don't match. This is powered by the `all-MiniLM-L6-v2` model via [fastembed](https://github.com/qdrant/fastembed).

**Note:** Semantic search requires the optional `semantic` dependencies:

```bash
# Install semantic search support
pip install cvec[semantic]
# or with uv:
uv pip install cvec[semantic]
```

```bash
# First, generate embeddings (one-time setup, ~10-60 min depending on dataset size)
cvec db build extract-embeddings

# Search using natural language
cvec search --semantic "memory corruption vulnerabilities in image processing"
cvec search --semantic "privilege escalation through kernel race conditions"
cvec search --semantic "SQL injection in web login forms"

# Adjust minimum similarity threshold (default: 0.3)
cvec search --semantic "buffer overflow" --min-similarity 0.5

# Combine with other filters
cvec search --semantic "remote code execution" --severity critical
cvec search --semantic "authentication bypass" --after 2024-01-01

# Output in different formats
cvec search --semantic "XSS attacks" --format json
```

### Get

Get detailed information about one or more CVEs:

```bash
cvec get CVE-2024-1234
cvec get CVE-2024-1234 CVE-2024-5678   # Multiple CVEs
cvec get CVE-2024-1234 --detailed       # Include all details
cvec get CVE-2024-1234 --format json
cvec get CVE-2024-1234 --output cve-details.json --format json
```

### Stats

Show database statistics:

```bash
cvec stats
cvec stats --format json
cvec stats --format markdown
cvec stats --output stats.json --format json
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

## Semantic Search

cvec supports semantic (natural language) search using sentence embeddings. This allows you to search for CVEs using descriptive phrases rather than exact keywords.

**This feature is optional** and requires additional dependencies (~500MB). Install with:

```bash
pip install cvec[semantic]
# or with uv:
uv pip install cvec[semantic]
```

### How it works

1. CVE titles and descriptions are concatenated and encoded into dense vector embeddings using the `all-MiniLM-L6-v2` model via [fastembed](https://github.com/qdrant/fastembed).
2. Your search query is encoded using the same model.
3. CVEs are ranked by cosine similarity between the query and CVE embeddings.

### Setup

After installing the semantic dependencies, generate embeddings:

```bash
cvec db update                          # Download CVE database
cvec db build extract-embeddings        # Generate embeddings (~10-60 min on CPU)
```

Alternatively, if the cvec-db repository provides pre-computed embeddings, they will be downloaded automatically when you have the semantic dependencies installed:

```bash
pip install cvec[semantic]        # Install semantic support
cvec db update                    # Downloads database + embeddings
```

### Model Details

- **Model**: `all-MiniLM-L6-v2`
- **Embedding dimension**: 384
- **Speed**: ~5× faster than larger models, suitable for CPU
- **Training**: 1B+ sentence pairs for broad semantic understanding

### Performance

- Embedding generation: ~300k CVEs in under 1 hour on a multi-core CPU
- Search queries: Near-instant (milliseconds)
- Storage: ~500MB for embeddings parquet file

## License

MIT
