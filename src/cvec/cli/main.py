"""CLI for CVE analysis tool.

This module provides a command-line interface for downloading, extracting,
and searching CVE data from the cvelistV5 repository.

Usage:
    cvec db update                     Update CVE database from pre-built parquet files
    cvec db update --prerelease        Update from latest pre-release
    cvec db status                     Show database status

    cvec db build download-json        Download raw JSON files (advanced)
    cvec db build extract-parquet      Extract JSON to parquet locally (advanced)
    cvec db build extract-embeddings   Generate embeddings for semantic search
    cvec db build create-manifest      Create manifest.json for distribution

    cvec search <query>                Search CVEs (use --semantic for semantic search)
    cvec get <cve-id>                  Get details for a specific CVE
    cvec products <query>              Search product/vendor names in the database
    cvec stats                         Show database statistics
"""

import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from cvec import MANIFEST_SCHEMA_VERSION
from cvec.core.config import Config
from cvec.services.downloader import DownloadService
from cvec.services.extractor import ExtractorService
from cvec.services.embeddings import (
    EmbeddingsService,
    SemanticDependencyError,
    is_semantic_available,
)
from cvec.services.artifact_fetcher import (
    ArtifactFetcher,
    ManifestIncompatibleError,
    ChecksumMismatchError,
    SUPPORTED_SCHEMA_VERSION,
)
from cvec.services.search import (
    SEVERITY_THRESHOLDS,
    CVESearchService,
    SearchMode,
    SearchResult,
    SeverityLevel,
)
from cvec.cli.formatters import (
    OutputFormat,
    output_search_results,
    output_cve_detail,
    output_products_table,
)

# Regex pattern to match CVE IDs
CVE_ID_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)

app = typer.Typer(
    name="cvec",
    help="CVE analysis tool for LLM agents",
    no_args_is_help=True,
)

# Database management subcommand group
db_app = typer.Typer(
    name="db",
    help="Database management commands",
    no_args_is_help=True,
)
app.add_typer(db_app, name="db")

# Build subcommand group for advanced/CI commands
build_app = typer.Typer(
    name="build",
    help="Advanced commands for building CVE database from source (used by CI)",
    no_args_is_help=True,
)
db_app.add_typer(build_app, name="build")

console = Console()


# =============================================================================
# Database Management Commands (db subcommand group)
# =============================================================================


@db_app.command("update")
def db_update(
    force: bool = typer.Option(
        False, "--force", "-f", help="Force update even if local is up-to-date"
    ),
    tag: Optional[str] = typer.Option(
        None, "--tag", "-t", help="Specific release tag to download"
    ),
    prerelease: bool = typer.Option(
        False, "--prerelease", "-p", help="Include pre-release versions"
    ),
    embeddings: bool = typer.Option(
        False, "--embeddings", "-e", help="Download embeddings for semantic search"
    ),
    repo: Optional[str] = typer.Option(
        None, "--repo", "-r", help="GitHub repo in 'owner/repo' format"
    ),
    data_dir: Optional[str] = typer.Option(
        None,
        "--data-dir",
        "-d",
        help="Override data directory (also used as download dir)",
    ),
) -> None:
    """Update CVE database from pre-built parquet files.

    This is the recommended way to get CVE data. It downloads pre-built
    parquet files from the cvec-db repository, which is much faster than
    downloading and processing raw JSON files.

    By default, embeddings are not downloaded. Use --embeddings to download
    them for semantic search support.

    Example:
        cvec db update
        cvec db update --force
        cvec db update --embeddings
        cvec db update --tag v20260106
        cvec db update --prerelease
        cvec db update --data-dir /path/to/data
    """
    data_path = Path(data_dir) if data_dir else None
    config = Config(data_dir=data_path, download_dir=data_path)
    fetcher = ArtifactFetcher(config, repo=repo)

    try:
        result = fetcher.update(
            tag=tag,
            force=force,
            include_prerelease=prerelease,
            include_embeddings=embeddings,
        )

        if result["status"] == "up-to-date":
            console.print("[green]✓ Database is already up-to-date.[/green]")
        else:
            stats = result.get("stats", {})
            tag_display = result["tag"]
            if result.get("is_prerelease"):
                tag_display += " (pre-release)"
            console.print(f"[green]✓ Updated to {tag_display}[/green]")
            console.print(f"  - CVEs: {stats.get('cves', 0)}")
            console.print(f"  - Downloaded {len(result['downloaded'])} files")
            if result.get("skipped_semantic"):
                console.print()
                console.print(
                    "[dim]Tip: Use 'cvec db update --embeddings' to download embeddings for semantic search.[/dim]"
                )

    except ManifestIncompatibleError as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print(
            "[yellow]Hint: Run 'pip install --upgrade cvec' to get the latest version.[/yellow]"
        )
        raise typer.Exit(1)
    except ChecksumMismatchError as e:
        console.print(f"[red]Error: {e}[/red]")
        console.print(
            "[yellow]Hint: Try running the command again. If the problem persists, the release may be corrupted.[/yellow]"
        )
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error updating database: {e}[/red]")
        raise typer.Exit(1)


@build_app.command("download-json")
def db_download_json(
    years: int = typer.Option(
        None, "--years", "-y", help="Number of years to download (default: from config)"
    ),
    all_data: bool = typer.Option(
        False, "--all", "-a", help="Download all data (CVEs, CWEs, CAPECs)"
    ),
    data_dir: Optional[str] = typer.Option(
        None,
        "--data-dir",
        "-d",
        help="Override data and download directory",
    ),
) -> None:
    """Download raw CVE JSON files from GitHub.

    This downloads the raw JSON files from the cvelistV5 repository.
    Use this if you need the original JSON data or want to build
    parquet files locally.

    For most users, 'cvec db update' is faster and easier.

    Example:
        cvec db build download-json
        cvec db build download-json --years 5
        cvec db build download-json --all
        cvec db build download-json --data-dir /path/to/data
    """
    data_path = Path(data_dir) if data_dir else None
    config = Config(data_dir=data_path, download_dir=data_path)
    if years:
        config.default_years = years

    service = DownloadService(config)

    if all_data:
        console.print("[blue]Downloading CAPEC data...[/blue]")
        service.download_capec()
        console.print("[green]✓ CAPEC downloaded[/green]\n")

        console.print("[blue]Downloading CWE data...[/blue]")
        service.download_cwe()
        console.print("[green]✓ CWE downloaded[/green]\n")

    console.print(
        f"[blue]Downloading CVE data (last {config.default_years} years)...[/blue]"
    )
    service.download_cves()
    console.print("[green]✓ CVE data downloaded[/green]\n")

    console.print("[blue]Extracting CVE JSON files...[/blue]")
    extracted = service.extract_cves()
    console.print(f"[green]✓ Extracted to {extracted}[/green]")

    console.print("\n[bold green]✓ Download complete![/bold green]")
    console.print(
        "[dim]Hint: Run 'cvec db extract-parquet' to convert to parquet format.[/dim]"
    )


@build_app.command("extract-parquet")
def db_extract_parquet(
    years: int = typer.Option(
        None, "--years", "-y", help="Number of years to process (default: from config)"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    data_dir: Optional[str] = typer.Option(
        None,
        "--data-dir",
        "-d",
        help="Override data and download directory",
    ),
) -> None:
    """Extract CVE JSON files to parquet format.

    This converts the downloaded JSON files into optimized parquet files.
    You must run 'cvec db build download-json' first.

    For most users, 'cvec db update' is faster and easier.

    Example:
        cvec db build extract-parquet
        cvec db build extract-parquet --years 5 --verbose
        cvec db build extract-parquet --data-dir /path/to/data
    """
    data_path = Path(data_dir) if data_dir else None
    config = Config(data_dir=data_path, download_dir=data_path)
    if years:
        config.default_years = years

    # Check if JSON files exist
    if not config.cve_dir.exists():
        console.print("[red]Error: No CVE JSON files found.[/red]")
        console.print("[yellow]Hint: Run 'cvec db build download-json' first.[/yellow]")
        raise typer.Exit(1)

    service = ExtractorService(config)

    console.print("[blue]Extracting CVE data...[/blue]")
    result = service.extract_all()

    stats = result.get("stats", {})

    console.print(f"[green]✓ Extracted {stats.get('cves', 0)} CVEs[/green]")

    if verbose:
        console.print(f"  - Descriptions: {stats.get('descriptions', 0)}")
        console.print(f"  - Metrics: {stats.get('metrics', 0)}")
        console.print(f"  - Products: {stats.get('products', 0)}")
        console.print(f"  - Versions: {stats.get('versions', 0)}")
        console.print(f"  - CWEs: {stats.get('cwes', 0)}")
        console.print(f"  - References: {stats.get('references', 0)}")
        console.print(f"  - Credits: {stats.get('credits', 0)}")
        console.print(f"  - Tags: {stats.get('tags', 0)}")

    console.print("[bold green]✓ Extraction complete![/bold green]")


@build_app.command("extract-embeddings")
def db_extract_embeddings(
    batch_size: int = typer.Option(
        256, "--batch-size", "-b", help="Number of CVEs to process per batch"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
    data_dir: Optional[str] = typer.Option(
        None,
        "--data-dir",
        "-d",
        help="Override data directory",
    ),
) -> None:
    """Generate embeddings for semantic search.

    This creates embeddings from CVE titles and descriptions using the
    all-MiniLM-L6-v2 model via fastembed. These embeddings enable
    semantic (natural language) search across CVEs.

    Requires the 'semantic' optional dependency:
        pip install 'cvec[semantic]'

    You must have parquet data first - run 'cvec db update' or 'cvec db build extract-parquet'.

    Example:
        cvec db build extract-embeddings
        cvec db build extract-embeddings --batch-size 512 --verbose
        cvec db build extract-embeddings --data-dir /path/to/data
    """
    # Check for semantic dependency
    if not is_semantic_available():
        console.print("[red]Error: Semantic search dependencies not installed.[/red]")
        console.print()
        console.print("Install with:")
        console.print("  [cyan]pip install cvec\\[semantic][/cyan]")
        console.print("  [dim]or with uv:[/dim]")
        console.print("  [cyan]uv pip install cvec\\[semantic][/cyan]")
        raise typer.Exit(1)

    data_path = Path(data_dir) if data_dir else None
    config = Config(data_dir=data_path)

    # Check if parquet files exist
    if not config.cves_parquet.exists():
        console.print("[red]Error: No CVE parquet data found.[/red]")
        console.print(
            "[yellow]Hint: Run 'cvec db update' or 'cvec db build extract-parquet' first.[/yellow]"
        )
        raise typer.Exit(1)

    console.print("[blue]Generating embeddings for semantic search...[/blue]")
    console.print(
        "[dim]Using model: sentence-transformers/all-MiniLM-L6-v2 (via fastembed)[/dim]"
    )

    try:
        service = EmbeddingsService(config, quiet=not verbose)
        result = service.extract_embeddings(batch_size=batch_size)

        console.print(f"[green]✓ Generated {result['count']} embeddings[/green]")
        console.print(f"  - Model: {result['model']}")
        console.print(f"  - Dimension: {result['dimension']}")
        console.print(f"  - Saved to: {result['path']}")

    except SemanticDependencyError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)
    except Exception as e:
        console.print(f"[red]Error generating embeddings: {e}[/red]")
        raise typer.Exit(1)


@build_app.command("create-manifest")
def db_create_manifest(
    data_dir: Optional[str] = typer.Option(
        None,
        "--data-dir",
        "-d",
        help="Override data directory containing parquet files",
    ),
    source: Optional[str] = typer.Option(
        None,
        "--source",
        "-s",
        help="Source identifier (e.g., 'ci', 'local', 'github-actions')",
    ),
    release_status: str = typer.Option(
        "draft",
        "--release-status",
        "-r",
        help="Release status: 'official', 'prerelease', or 'draft' (default: draft)",
    ),
    output: Optional[str] = typer.Option(
        None,
        "--output",
        "-o",
        help="Output path for manifest.json (default: <data-dir>/manifest.json)",
    ),
) -> None:
    """Create manifest.json for distribution.

    Generates a manifest file from the extracted parquet files. The manifest
    includes file checksums, statistics, and metadata required for the
    pre-built database distribution.

    This command is primarily used by CI/CD pipelines to create release artifacts.

    Example:
        cvec db build create-manifest
        cvec db build create-manifest --source github-actions --release-status official
        cvec db build create-manifest --release-status prerelease
        cvec db build create-manifest --data-dir /path/to/data --output manifest.json
    """
    import polars as pl

    data_path = Path(data_dir) if data_dir else None
    config = Config(data_dir=data_path)

    # Check if parquet files exist
    if not config.cves_parquet.exists():
        console.print("[red]Error: No CVE parquet data found.[/red]")
        console.print(
            "[yellow]Hint: Run 'cvec db build extract-parquet' first.[/yellow]"
        )
        raise typer.Exit(1)

    console.print("[blue]Creating manifest...[/blue]")

    # List of parquet files to include in manifest
    parquet_files = [
        "cves.parquet",
        "cve_descriptions.parquet",
        "cve_metrics.parquet",
        "cve_products.parquet",
        "cve_versions.parquet",
        "cve_cwes.parquet",
        "cve_references.parquet",
        "cve_credits.parquet",
        "cve_tags.parquet",
    ]

    # Optionally include embeddings if they exist
    embeddings_path = config.data_dir / "cve_embeddings.parquet"
    if embeddings_path.exists():
        parquet_files.append("cve_embeddings.parquet")

    # Build files list with checksums
    files_info = []
    for filename in parquet_files:
        file_path = config.data_dir / filename
        if file_path.exists():
            # Calculate SHA256
            sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    sha256.update(chunk)

            files_info.append(
                {
                    "name": filename,
                    "sha256": sha256.hexdigest(),
                    "size": file_path.stat().st_size,
                }
            )
        else:
            console.print(f"[yellow]Warning: {filename} not found, skipping[/yellow]")

    # Gather stats from CVEs parquet
    stats = {}
    try:
        df_cves = pl.read_parquet(config.cves_parquet)
        stats["cves"] = len(df_cves)
    except Exception as e:
        console.print(f"[yellow]Warning: Could not read CVEs stats: {e}[/yellow]")

    # Validate release_status
    valid_statuses = ["official", "prerelease", "draft"]
    if release_status not in valid_statuses:
        console.print(
            f"[red]Error: Invalid release status '{release_status}'. "
            f"Must be one of: {', '.join(valid_statuses)}[/red]"
        )
        raise typer.Exit(1)

    # Build manifest
    manifest = {
        "schema_version": MANIFEST_SCHEMA_VERSION,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "release_status": release_status,
        "stats": stats,
        "files": files_info,
    }

    # Add source if provided
    if source:
        manifest["source"] = source

    # Determine output path
    output_path = Path(output) if output else config.data_dir / "manifest.json"

    # Write manifest
    output_path.write_text(json.dumps(manifest, indent=2))

    console.print(f"[green]✓ Manifest created: {output_path}[/green]")
    console.print(f"  - Schema version: {MANIFEST_SCHEMA_VERSION}")
    console.print(f"  - Release status: {release_status}")
    console.print(f"  - Files: {len(files_info)}")
    console.print(f"  - CVEs: {stats.get('cves', 'unknown')}")
    if source:
        console.print(f"  - Source: {source}")


@db_app.command("status")
def db_status(
    repo: Optional[str] = typer.Option(
        None, "--repo", "-r", help="GitHub repo in 'owner/repo' format"
    ),
    data_dir: Optional[str] = typer.Option(
        None,
        "--data-dir",
        "-d",
        help="Override data directory",
    ),
) -> None:
    """Show database status and check for updates.

    Displays information about the local database and checks if
    a newer version is available from the cvec-db repository.

    Example:
        cvec db status
        cvec db status --data-dir /path/to/data
    """
    data_path = Path(data_dir) if data_dir else None
    config = Config(data_dir=data_path)
    fetcher = ArtifactFetcher(config, repo=repo)

    console.print("[bold]CVE Database Status[/bold]\n")

    # Local status
    local_manifest = fetcher.get_local_manifest()
    if local_manifest:
        console.print("[green]✓ Local database found[/green]")
        console.print(
            f"  - Schema version: {local_manifest.get('schema_version', 'unknown')}"
        )
        console.print(f"  - Generated: {local_manifest.get('generated_at', 'unknown')}")
        stats = local_manifest.get("stats", {})
        console.print(f"  - CVEs: {stats.get('cves', 'unknown')}")
        console.print(f"  - Files: {len(local_manifest.get('files', []))}")
    else:
        console.print("[yellow]⚠ No local database found[/yellow]")
        console.print("  Run 'cvec db update' to download the database.")

    console.print()

    # Semantic search capability status
    if is_semantic_available():
        embeddings_service = EmbeddingsService(config, quiet=True)
        embeddings_stats = embeddings_service.get_stats()
        if embeddings_stats:
            console.print("[green]✓ Semantic search enabled[/green]")
            console.print(f"  - Embeddings: {embeddings_stats['count']}")
            console.print(f"  - Model: {embeddings_stats['model']}")
        else:
            console.print(
                "[yellow]⚠ Semantic search available but no embeddings[/yellow]"
            )
            console.print(
                "  Run 'cvec db build extract-embeddings' to generate embeddings."
            )
    else:
        console.print("[dim]⚠ Semantic search not installed[/dim]")
        console.print("  Install with: pip install cvec\\[semantic]")

    console.print()

    # Remote status
    try:
        status = fetcher.status()

        if status["remote"]["available"]:
            remote = status["remote"]["manifest"]
            console.print("[green]✓ Remote database available[/green]")
            console.print(
                f"  - Schema version: {remote.get('schema_version', 'unknown')}"
            )
            console.print(f"  - Generated: {remote.get('generated_at', 'unknown')}")
            remote_stats = remote.get("stats", {})
            console.print(f"  - CVEs: {remote_stats.get('cves', 'unknown')}")

            if status["needs_update"]:
                console.print("\n[yellow]⚠ Update available![/yellow]")
                console.print("  Run 'cvec db update' to download the latest version.")
            else:
                console.print("\n[green]✓ Local database is up-to-date[/green]")
        else:
            console.print("[yellow]⚠ Could not check remote database[/yellow]")
    except Exception as e:
        console.print(f"[yellow]⚠ Could not check remote database: {e}[/yellow]")

    console.print()
    console.print(f"[dim]Supported schema version: {SUPPORTED_SCHEMA_VERSION}[/dim]")
    console.print(f"[dim]Data directory: {config.data_dir}[/dim]")


@app.command()
def search(
    query: Optional[str] = typer.Argument(
        None,
        help="Search query (product name, vendor, CWE ID, CPE string, or natural language for semantic search). Optional when using --product, --vendor, or --cpe filters.",
    ),
    cpe: Optional[str] = typer.Option(
        None,
        "--cpe",
        "-c",
        help="Search by CPE string (e.g., cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*)",
    ),
    version: Optional[str] = typer.Option(
        None,
        "--version",
        "-e",
        help="Filter by version (only show CVEs affecting this version)",
    ),
    mode: Optional[str] = typer.Option(
        None,
        "--mode",
        "-M",
        help="Search mode: strict (exact match), regex (pattern), fuzzy (substring, default), semantic (AI)",
    ),
    semantic: bool = typer.Option(
        False,
        "--semantic",
        "-m",
        help="Use semantic (natural language) search (shortcut for --mode semantic)",
    ),
    vendor: Optional[str] = typer.Option(
        None, "--vendor", "-V", help="Filter by vendor name"
    ),
    product: Optional[str] = typer.Option(
        None, "--product", "-p", help="Filter by product name"
    ),
    severity: Optional[str] = typer.Option(
        None,
        "--severity",
        "-s",
        help="Filter by severity (low, medium, high, critical)",
    ),
    state: Optional[str] = typer.Option(
        None,
        "--state",
        "-S",
        help="Filter by CVE state (published, rejected)",
    ),
    after: Optional[str] = typer.Option(
        None, "--after", help="Only CVEs published after this date (YYYY-MM-DD)"
    ),
    before: Optional[str] = typer.Option(
        None, "--before", help="Only CVEs published before this date (YYYY-MM-DD)"
    ),
    kev: bool = typer.Option(
        False,
        "--kev",
        "-k",
        help="Only show CVEs in CISA Known Exploited Vulnerabilities",
    ),
    min_similarity: float = typer.Option(
        0.3,
        "--min-similarity",
        help="Minimum similarity score for semantic search (0-1)",
    ),
    limit: int = typer.Option(
        100, "--limit", "-n", help="Maximum number of results to show"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, markdown"
    ),
    detailed: bool = typer.Option(
        False, "--detailed", "-d", help="Show detailed output with descriptions"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show summary statistics"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Write output to file (no truncation when used)"
    ),
) -> None:
    """Search CVEs by product name, vendor, CWE ID, CPE, or natural language.

    Search Modes:
    - fuzzy (default): Case-insensitive substring matching
    - strict: Exact case-insensitive match
    - regex: Regular expression pattern matching
    - semantic: Natural language AI-powered search (requires embeddings)

    CPE Search:
    Search by CPE (Common Platform Enumeration) string to find vulnerabilities
    for specific software. Use --version to filter to only CVEs that affect
    your specific version.

    Examples:
        cvec search "linux kernel"              # Fuzzy search (default)
        cvec search "linux" --mode strict       # Exact match only
        cvec search "linux.*kernel" --mode regex # Regex pattern
        cvec search "memory corruption" -m      # Semantic search
        cvec search "windows" -V microsoft      # Filter by vendor
        cvec search "chrome" -p browser         # Filter by product
        cvec search "apache" -d                 # Show with descriptions
        cvec search --cpe "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"  # CPE search
        cvec search --cpe "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*" --version 2.4.51  # Version filter
        cvec search "apache" --version 2.4.51   # Filter by version
    """
    config = Config()
    service = CVESearchService(config)

    # CPE search takes precedence
    if cpe:
        try:
            result = service.by_cpe(cpe, check_version=version)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)
    # Product/vendor filter without query
    elif (product or vendor) and not query:
        # Search by product/vendor filter only
        if product and vendor:
            # Use the unified search with both filters
            result = service.by_product(product, vendor=vendor, fuzzy=True, exact=True)
        elif product:
            result = service.by_product(product, fuzzy=True, exact=True)
        elif vendor:
            result = service.by_vendor(vendor, fuzzy=True, exact=True)
        
        # Apply version filter if specified
        if version and result.count > 0:
            result = service.filter_by_version(
                result, version=version, vendor=vendor, product=product
            )
    else:
        # Validate non-empty query when not using filters
        if not query or not query.strip():
            console.print("[red]Error: Search query, --product, --vendor, or --cpe option required.[/red]")
            raise typer.Exit(1)

        query = query.strip()

        # Determine search mode
        search_mode = SearchMode.FUZZY  # Default
        if semantic or mode == "semantic":
            search_mode = SearchMode.SEMANTIC
        elif mode == "strict":
            search_mode = SearchMode.STRICT
        elif mode == "regex":
            search_mode = SearchMode.REGEX
        elif mode == "fuzzy" or mode is None:
            search_mode = SearchMode.FUZZY
        elif mode:
            console.print(
                f"[red]Invalid mode: {mode}. Must be: strict, regex, fuzzy, semantic[/red]"
            )
            raise typer.Exit(1)

        # Semantic search mode
        if search_mode == SearchMode.SEMANTIC:
            # Check if embeddings are available
            if not service.has_embeddings():
                console.print(
                    "[red]Error: Embeddings not found for semantic search.[/red]"
                )
                console.print()
                console.print("Download embeddings with:")
                console.print("  [cyan]cvec db update --embeddings[/cyan]")
                console.print()
                console.print("Or generate them locally with:")
                console.print("  [cyan]cvec db build extract-embeddings[/cyan]")
                raise typer.Exit(1)

            # Check if semantic dependencies are installed
            if not is_semantic_available():
                console.print(
                    "[red]Error: Semantic search dependencies not installed.[/red]"
                )
                console.print()
                console.print("Install with:")
                console.print("  [cyan]pip install cvec\\[semantic][/cyan]")
                console.print("  [dim]or with uv:[/dim]")
                console.print("  [cyan]uv pip install cvec\\[semantic][/cyan]")
                raise typer.Exit(1)

            try:
                result = service.semantic_search(
                    query, top_k=limit, min_similarity=min_similarity
                )
            except SemanticDependencyError as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)
            except Exception as e:
                console.print(f"[red]Error in semantic search: {e}[/red]")
                raise typer.Exit(1)
        # Auto-detect CVE ID format and redirect to get command behavior
        elif CVE_ID_PATTERN.match(query):
            result = service.by_id(query)
            if len(result.cves) == 0:
                console.print(f"[red]CVE not found: {query}[/red]")
                raise typer.Exit(1)
        # Auto-detect CPE format in query
        elif query.lower().startswith("cpe:"):
            try:
                result = service.by_cpe(query, check_version=version)
            except ValueError as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)
        # Determine search type based on query format
        elif query.upper().startswith("CWE"):
            result = service.by_cwe(query)
        else:
            # Use the unified search method with mode
            try:
                result = service.search(
                    query,
                    mode=search_mode,
                    vendor=vendor,
                    product_filter=product,
                )
            except ValueError as e:
                console.print(f"[red]Error: {e}[/red]")
                raise typer.Exit(1)

        # Apply version filter for non-CPE searches (CPE already handles it)
        if version and result.count > 0 and not (query and query.lower().startswith("cpe:")):
            result = service.filter_by_version(
                result, version=version, vendor=vendor, product=product
            )

    # Apply state filter
    if state:
        result = service.filter_by_state(result, state)

    # Apply KEV filter
    if kev:
        result = service.filter_by_kev(result)

    # Apply date filters
    if after or before:
        try:
            result = service.filter_by_date(result, after=after, before=before)
        except ValueError as e:
            console.print(f"[red]Error: {e}[/red]")
            raise typer.Exit(1)

    # Apply severity filter
    if severity:
        sev_lower = severity.lower()
        if sev_lower not in SEVERITY_THRESHOLDS:
            console.print(
                f"[red]Invalid severity: {severity}. Must be: none, low, medium, high, critical[/red]"
            )
            raise typer.Exit(1)

        # Cast to SeverityLevel type
        sev: SeverityLevel = sev_lower  # type: ignore[assignment]
        result = service.filter_by_severity(result, sev)

    output_search_results(
        result,
        format=format,
        verbose=verbose,
        limit=limit,
        search_service=service,
        output_file=output,
        detailed=detailed,
    )


@app.command()
def get(
    cve_id: str = typer.Argument(..., help="CVE ID (e.g., CVE-2024-1234)"),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, markdown"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show all available details"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Write output to file"
    ),
) -> None:
    """Get details for a specific CVE."""
    config = Config()
    service = CVESearchService(config)

    result = service.by_id(cve_id)

    if len(result.cves) == 0:
        console.print(f"[red]CVE not found: {cve_id}[/red]")
        raise typer.Exit(1)

    row = result.cves.to_dicts()[0]
    output_cve_detail(
        row,
        result,
        service,
        format=format,
        verbose=verbose,
        output_file=output,
    )


@app.command()
def stats(
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, markdown"
    ),
) -> None:
    """Show database statistics."""
    config = Config()
    service = CVESearchService(config)

    try:
        statistics = service.stats()
    except FileNotFoundError:
        console.print("[red]No data found. Run 'cvec db update' first.[/red]")
        raise typer.Exit(1)

    if format == OutputFormat.JSON:
        print(json.dumps(statistics, indent=2))

    elif format == OutputFormat.MARKDOWN:
        print("# CVE Database Statistics\n")
        print(f"**Total CVEs:** {statistics['total_cves']}\n")
        print(f"**CVEs with CVSS:** {statistics['cves_with_cvss']}\n")
        print(f"**Unique Products:** {statistics['unique_products']}\n")
        print(f"**Unique Vendors:** {statistics['unique_vendors']}\n")
        print(f"**Unique CWEs:** {statistics['unique_cwes']}\n")
        print(f"**Total References:** {statistics['total_references']}\n")

        print("\n## CVEs by State\n")
        for state, count in statistics.get("states", {}).items():
            print(f"- {state}: {count}")

        print("\n## CVEs by Year\n")
        for year, count in statistics.get("by_year", {}).items():
            print(f"- {year}: {count}")

    else:
        console.print(
            Panel(
                f"[bold]Total CVEs:[/bold] {statistics['total_cves']}\n"
                f"[bold]CVEs with CVSS:[/bold] {statistics['cves_with_cvss']}\n"
                f"[bold]Product Entries:[/bold] {statistics['total_product_entries']}\n"
                f"[bold]Unique Products:[/bold] {statistics['unique_products']}\n"
                f"[bold]Unique Vendors:[/bold] {statistics['unique_vendors']}\n"
                f"[bold]Unique CWEs:[/bold] {statistics['unique_cwes']}\n"
                f"[bold]Total References:[/bold] {statistics['total_references']}",
                title="CVE Database Statistics",
            )
        )

        if statistics.get("states"):
            table = Table(title="CVEs by State")
            table.add_column("State")
            table.add_column("Count", justify="right")
            for state, count in statistics.get("states", {}).items():
                table.add_row(state, str(count))
            console.print(table)

        if statistics.get("by_year"):
            table = Table(title="CVEs by Year (recent)")
            table.add_column("Year")
            table.add_column("Count", justify="right")
            years = sorted(statistics.get("by_year", {}).items(), reverse=True)[:10]
            for year, count in years:
                table.add_row(year, str(count))
            console.print(table)


@app.command()
def recent(
    days: int = typer.Option(30, "--days", "-d", help="Number of days to look back"),
    limit: int = typer.Option(
        50, "--limit", "-n", help="Maximum number of results to show"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, markdown"
    ),
    detailed: bool = typer.Option(
        False, "--detailed", help="Show detailed output with descriptions"
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show summary statistics"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Write output to file (no truncation when used)"
    ),
) -> None:
    """Show recently published CVEs."""
    config = Config()
    service = CVESearchService(config)

    result = service.recent(days=days)

    if len(result.cves) == 0:
        console.print(f"[yellow]No CVEs found in the last {days} days.[/yellow]")
        return

    output_search_results(
        result,
        format=format,
        verbose=verbose,
        limit=limit,
        search_service=service,
        output_file=output,
        detailed=detailed,
    )


@app.command()
def products(
    query: str = typer.Argument(
        ...,
        help="Search query for product or vendor name",
    ),
    mode: Optional[str] = typer.Option(
        None,
        "--mode",
        "-M",
        help="Search mode: strict (exact match), regex (pattern), fuzzy (substring, default)",
    ),
    vendor: Optional[str] = typer.Option(
        None, "--vendor", "-V", help="Filter by vendor name"
    ),
    limit: int = typer.Option(
        100, "--limit", "-n", help="Maximum number of results to show"
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help="Output format: table, json, markdown"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Write output to file"
    ),
) -> None:
    """Search product/vendor names in the CVE database.

    This command helps you discover the exact product and vendor names
    used in the CVE database, which is useful for refining CVE searches.

    The results show how many CVEs affect each product/vendor combination.

    Examples:
        cvec products "linux"                # Find all products with "linux"
        cvec products "chrome" -V google     # Chrome products by Google
        cvec products "windows" --mode strict # Exact match for "windows"
        cvec products "apache.*http" -M regex # Regex pattern
    """
    config = Config()
    service = CVESearchService(config)

    # Validate non-empty query
    if not query or not query.strip():
        console.print("[red]Error: Search query cannot be empty.[/red]")
        raise typer.Exit(1)

    query = query.strip()

    # Determine search mode
    search_mode = SearchMode.FUZZY  # Default
    if mode == "strict":
        search_mode = SearchMode.STRICT
    elif mode == "regex":
        search_mode = SearchMode.REGEX
    elif mode == "fuzzy" or mode is None:
        search_mode = SearchMode.FUZZY
    elif mode:
        console.print(f"[red]Invalid mode: {mode}. Must be: strict, regex, fuzzy[/red]")
        raise typer.Exit(1)

    try:
        products_df = service.search_products(
            query,
            mode=search_mode,
            vendor=vendor,
            limit=limit,
        )
    except ValueError as e:
        console.print(f"[red]Error: {e}[/red]")
        raise typer.Exit(1)

    output_products_table(
        products_df,
        limit=limit,
        format=format,
        output_file=output,
    )


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
