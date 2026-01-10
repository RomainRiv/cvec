"""CLI for CVE analysis tool.

This module provides a command-line interface for downloading, extracting,
and searching CVE data from the cvelistV5 repository.

Usage:
    cvec db update               Update CVE database from pre-built parquet files
    cvec db download-json        Download raw JSON files (advanced)
    cvec db extract-parquet      Extract JSON to parquet locally (advanced)
    cvec db extract-embeddings   Generate embeddings for semantic search
    cvec db status               Show database status
    cvec search <query>          Search CVEs (use --semantic for semantic search)
    cvec get <cve-id>            Get details for a specific CVE
    cvec stats                   Show database statistics
"""

import json
import re
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

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
    SearchResult,
    SeverityLevel,
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

console = Console()


# Output format options
class OutputFormat:
    JSON = "json"
    TABLE = "table"
    MARKDOWN = "markdown"


def _get_severity(
    row: dict, search_service: Optional[CVESearchService] = None
) -> tuple[str, str]:
    """Get severity score and version as separate values.

    Returns a tuple of (score_str, version_str).
    - score_str: "8.1" or "High" or "-"
    - version_str: "v3.1", "v4.0*", "text", or "-"

    ADP scores are marked with * (e.g., "v3.1*").
    """
    cve_id = row.get("cve_id", "")

    # If we have a search service, use it to get the best metric
    if search_service:
        metric = search_service.get_best_metric(cve_id)
        if metric:
            score = metric.get("base_score")
            metric_type = metric.get("metric_type", "")
            source = metric.get("source", "cna")
            base_severity = metric.get("base_severity")

            # Build version string
            version = "v?"
            if "V4" in metric_type.upper():
                version = "v4.0"
            elif "V3_1" in metric_type.upper():
                version = "v3.1"
            elif "V3_0" in metric_type.upper():
                version = "v3.0"
            elif "V2" in metric_type.upper():
                version = "v2.0"
            elif metric_type == "other" or not metric_type.startswith("cvss"):
                version = "text"

            # Mark ADP scores with *
            if source.startswith("adp:"):
                version = f"{version}*"

            if score is not None:
                return f"{score:.1f}", version
            elif base_severity:
                # Text severity only (no numeric score)
                return str(base_severity), "text"

    return "-", "-"


def _output_result(
    result: SearchResult,
    format: str = OutputFormat.TABLE,
    verbose: bool = False,
    limit: int = 100,
    search_service: Optional[CVESearchService] = None,
    output_file: Optional[str] = None,
) -> None:
    """Output search result in the specified format.

    Args:
        result: Search results to output
        format: Output format (table, json, markdown)
        verbose: Include detailed information
        limit: Maximum number of results (ignored when output_file is specified)
        search_service: Service for getting severity info
        output_file: Path to write output file (if specified, no truncation)
    """
    df = result.cves

    if len(df) == 0:
        if output_file:
            # Still write empty result to file
            pass
        else:
            console.print("[yellow]No results found.[/yellow]")
            return

    # When writing to file, don't truncate
    truncated = False if output_file else len(df) > limit
    total_count = len(df)
    if truncated:
        df = df.head(limit)

    if format == OutputFormat.JSON:
        # JSON output for LLM consumption - add severity info to each record
        records = []
        for row in df.iter_rows(named=True):
            record = dict(row)
            if search_service:
                severity, version = _get_severity(row, search_service)
                record["severity"] = severity
                record["cvss_version"] = version
            records.append(record)

        if verbose:
            output: object = {
                "count": total_count,
                "showing": len(records),
                "truncated": truncated,
                "results": records,
                "summary": result.summary(),
            }
        else:
            output = {
                "count": total_count,
                "showing": len(records),
                "truncated": truncated,
                "results": records,
            }

        json_output = json.dumps(output, indent=2, default=str)
        if output_file:
            from pathlib import Path

            Path(output_file).write_text(json_output)
            console.print(f"[green]Output written to {output_file}[/green]")
        else:
            print(json_output)

    elif format == OutputFormat.MARKDOWN:
        # Markdown output for LLM consumption
        lines = []
        lines.append("# CVE Search Results\n")
        lines.append(
            f"Found **{total_count}** CVEs"
            + (f" (showing first {limit})" if truncated else "")
            + "\n"
        )

        if verbose:
            summary = result.summary()
            lines.append("## Summary\n")
            lines.append(f"- Severity: {summary.get('severity_distribution', {})}")
            lines.append(f"- Years: {summary.get('year_distribution', {})}")
            lines.append("")

        lines.append("## Results\n")
        lines.append("| CVE ID | State | Title | Severity | Version |")
        lines.append("|--------|-------|-------|----------|---------|")
        for row in df.iter_rows(named=True):
            cve_id = row.get("cve_id", "")
            state = row.get("state", "")
            title = (row.get("cna_title") or "")[:50]
            severity, version = _get_severity(row, search_service)
            lines.append(f"| {cve_id} | {state} | {title} | {severity} | {version} |")

        markdown_output = "\n".join(lines)
        if output_file:
            from pathlib import Path

            Path(output_file).write_text(markdown_output)
            console.print(f"[green]Output written to {output_file}[/green]")
        else:
            print(markdown_output)

    else:
        # Table output for human consumption
        if truncated:
            console.print(
                f"[yellow]Showing first {limit} of {total_count} results[/yellow]"
            )

        table = Table(title=f"CVE Results ({total_count} total)")
        table.add_column("CVE ID", style="cyan")
        table.add_column("State", style="green")
        table.add_column("Title")
        table.add_column("Severity", justify="right")
        table.add_column("Version", justify="center")
        table.add_column("Published")

        for row in df.iter_rows(named=True):
            cve_id = row.get("cve_id", "")
            state = row.get("state", "")
            title = (row.get("cna_title") or "")[:60]
            severity, version = _get_severity(row, search_service)
            published = str(row.get("date_published") or "")[:10]
            table.add_row(cve_id, state, title, severity, version, published)

        console.print(table)

        if verbose:
            summary = result.summary()
            console.print(
                Panel(
                    f"Severity: {summary.get('severity_distribution', {})}\n"
                    f"Years: {summary.get('year_distribution', {})}",
                    title="Summary",
                )
            )


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
    repo: Optional[str] = typer.Option(
        None, "--repo", "-r", help="GitHub repo in 'owner/repo' format"
    ),
) -> None:
    """Update CVE database from pre-built parquet files.

    This is the recommended way to get CVE data. It downloads pre-built
    parquet files from the cvec-db repository, which is much faster than
    downloading and processing raw JSON files.

    Example:
        cvec db update
        cvec db update --force
        cvec db update --tag v20260106
    """
    config = Config()
    fetcher = ArtifactFetcher(config, repo=repo)

    try:
        result = fetcher.update(tag=tag, force=force)

        if result["status"] == "up-to-date":
            console.print("[green]✓ Database is already up-to-date.[/green]")
        else:
            stats = result.get("stats", {})
            console.print(f"[green]✓ Updated to {result['tag']}[/green]")
            console.print(f"  - CVEs: {stats.get('cves', 0)}")
            console.print(f"  - Downloaded {len(result['downloaded'])} files")

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


@db_app.command("download-json")
def db_download_json(
    years: int = typer.Option(
        None, "--years", "-y", help="Number of years to download (default: from config)"
    ),
    all_data: bool = typer.Option(
        False, "--all", "-a", help="Download all data (CVEs, CWEs, CAPECs)"
    ),
) -> None:
    """Download raw CVE JSON files from GitHub.

    This downloads the raw JSON files from the cvelistV5 repository.
    Use this if you need the original JSON data or want to build
    parquet files locally.

    For most users, 'cvec db update' is faster and easier.

    Example:
        cvec db download-json
        cvec db download-json --years 5
        cvec db download-json --all
    """
    config = Config()
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


@db_app.command("extract-parquet")
def db_extract_parquet(
    years: int = typer.Option(
        None, "--years", "-y", help="Number of years to process (default: from config)"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
) -> None:
    """Extract CVE JSON files to parquet format.

    This converts the downloaded JSON files into optimized parquet files.
    You must run 'cvec db download-json' first.

    For most users, 'cvec db update' is faster and easier.

    Example:
        cvec db extract-parquet
        cvec db extract-parquet --years 5 --verbose
    """
    config = Config()
    if years:
        config.default_years = years

    # Check if JSON files exist
    if not config.cve_dir.exists():
        console.print("[red]Error: No CVE JSON files found.[/red]")
        console.print("[yellow]Hint: Run 'cvec db download-json' first.[/yellow]")
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


@db_app.command("extract-embeddings")
def db_extract_embeddings(
    batch_size: int = typer.Option(
        256, "--batch-size", "-b", help="Number of CVEs to process per batch"
    ),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
) -> None:
    """Generate embeddings for semantic search.

    This creates embeddings from CVE titles and descriptions using the
    all-MiniLM-L6-v2 model via fastembed. These embeddings enable
    semantic (natural language) search across CVEs.

    Requires the 'semantic' optional dependency:
        pip install 'cvec[semantic]'

    You must have parquet data first - run 'cvec db update' or 'cvec db extract-parquet'.

    Example:
        cvec db extract-embeddings
        cvec db extract-embeddings --batch-size 512 --verbose
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

    config = Config()

    # Check if parquet files exist
    if not config.cves_parquet.exists():
        console.print("[red]Error: No CVE parquet data found.[/red]")
        console.print("[yellow]Hint: Run 'cvec db update' first.[/yellow]")
        raise typer.Exit(1)

    console.print("[blue]Generating embeddings for semantic search...[/blue]")
    console.print("[dim]Using model: sentence-transformers/all-MiniLM-L6-v2 (via fastembed)[/dim]")

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


@db_app.command("status")
def db_status(
    repo: Optional[str] = typer.Option(
        None, "--repo", "-r", help="GitHub repo in 'owner/repo' format"
    ),
) -> None:
    """Show database status and check for updates.

    Displays information about the local database and checks if
    a newer version is available from the cvec-db repository.

    Example:
        cvec db status
    """
    config = Config()
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
            console.print("  Run 'cvec db extract-embeddings' to generate embeddings.")
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
    query: str = typer.Argument(
        ...,
        help="Search query (product name, vendor, CWE ID, or natural language for semantic search)",
    ),
    semantic: bool = typer.Option(
        False,
        "--semantic",
        "-m",
        help="Use semantic (natural language) search instead of keyword matching",
    ),
    vendor: Optional[str] = typer.Option(
        None, "--vendor", "-V", help="Filter by vendor name"
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
    exact: bool = typer.Option(
        False, "--exact", "-e", help="Use exact literal matching (no regex)"
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
    verbose: bool = typer.Option(
        False, "--verbose", "-v", help="Show detailed output with summary statistics"
    ),
    output: Optional[str] = typer.Option(
        None, "--output", "-o", help="Write output to file (no truncation when used)"
    ),
) -> None:
    """Search CVEs by product name, vendor, CWE ID, or natural language.

    Use --semantic for natural language semantic search (requires embeddings
    and the 'semantic' optional dependency: pip install cvec[semantic]).
    """
    config = Config()
    service = CVESearchService(config)

    # Validate non-empty query
    if not query or not query.strip():
        console.print("[red]Error: Search query cannot be empty.[/red]")
        raise typer.Exit(1)

    query = query.strip()

    # Semantic search mode
    if semantic:
        # Check if semantic dependencies are installed
        if not is_semantic_available():
            console.print(
                "[red]Error: Semantic search dependencies not installed.[/red]"
            )
            console.print()
            console.print("Install with:")
            console.print("  [cyan]pip install cvec\\\\[semantic][/cyan]")
            console.print("  [dim]or with uv:[/dim]")
            console.print("  [cyan]uv pip install cvec\\\\[semantic][/cyan]")
            raise typer.Exit(1)

        if not service.has_embeddings():
            console.print("[red]Error: Embeddings not found for semantic search.[/red]")
            console.print(
                "[yellow]Hint: Run 'cvec db extract-embeddings' first.[/yellow]"
            )
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
    # Determine search type based on query format
    elif query.upper().startswith("CWE"):
        result = service.by_cwe(query)
    elif vendor:
        result = service.by_product(query, vendor=vendor, exact=exact)
    else:
        # Try product search first
        result = service.by_product(query, exact=exact)

        # If no results, try vendor search
        if len(result.cves) == 0:
            result = service.by_vendor(query, exact=exact)

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

    _output_result(
        result,
        format=format,
        verbose=verbose,
        limit=limit,
        search_service=service,
        output_file=output,
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
    description = service.get_description(row.get("cve_id", ""))
    best_metric = service.get_best_metric(row.get("cve_id", ""))
    kev_info = service.get_kev_info(row.get("cve_id", ""))
    ssvc_info = service.get_ssvc_info(row.get("cve_id", ""))

    # Deduplicate references by URL
    unique_refs: list[dict] = []
    seen_urls: set[str] = set()
    if result.references is not None and len(result.references) > 0:
        for ref in result.references.iter_rows(named=True):
            url = ref.get("url", "")
            if url and url not in seen_urls:
                seen_urls.add(url)
                unique_refs.append(dict(ref))

    if format == OutputFormat.JSON:
        output_data = row.copy()
        if description:
            output_data["description"] = description
        if best_metric:
            output_data["best_metric"] = best_metric
        if kev_info:
            output_data["kev_info"] = kev_info
        if ssvc_info:
            output_data["ssvc_info"] = ssvc_info
        if result.products is not None and len(result.products) > 0:
            output_data["affected_products"] = result.products.to_dicts()
        if result.cwes is not None and len(result.cwes) > 0:
            output_data["cwes"] = result.cwes.to_dicts()
        if unique_refs:
            output_data["references"] = unique_refs

        json_output = json.dumps(output_data, indent=2, default=str)
        if output:
            from pathlib import Path

            Path(output).write_text(json_output)
            console.print(f"[green]Output written to {output}[/green]")
        else:
            print(json_output)

    elif format == OutputFormat.MARKDOWN:
        lines = []
        lines.append(f"# {row.get('cve_id')}\n")
        lines.append(f"**State:** {row.get('state')}\n")
        if row.get("cna_title"):
            lines.append(f"**Title:** {row.get('cna_title')}\n")
        lines.append(f"**Published:** {row.get('date_published')}\n")

        if best_metric:
            score = best_metric.get("base_score")
            metric_type = best_metric.get("metric_type", "")
            if score:
                lines.append(f"**CVSS Score:** {score} ({metric_type})\n")

        if kev_info:
            date_added = kev_info.get("dateAdded", "Unknown")
            lines.append(
                f"**⚠️ Known Exploited Vulnerability:** Added to KEV on {date_added}\n"
            )

        if description:
            lines.append(f"## Description\n\n{description}\n")

        if result.products is not None and len(result.products) > 0:
            lines.append("## Affected Products\n")
            for prod in result.products.iter_rows(named=True):
                vendor = prod.get("vendor", "")
                product = prod.get("product", "")
                lines.append(f"- {vendor}: {product}")

        if result.cwes is not None and len(result.cwes) > 0:
            lines.append("\n## CWEs\n")
            for cwe in result.cwes.iter_rows(named=True):
                cwe_id = cwe.get("cwe_id")
                cwe_desc = cwe.get("description", "")
                # Handle missing CWE IDs
                if cwe_id:
                    lines.append(f"- {cwe_id}: {cwe_desc}")
                elif cwe_desc:
                    lines.append(f"- (No CWE ID): {cwe_desc}")

        if unique_refs:
            lines.append("\n## References\n")
            for ref in unique_refs:
                url = ref.get("url", "")
                tags = ref.get("tags", "")
                # Filter out x_transferred tags for cleaner output
                if tags:
                    clean_tags = ",".join(
                        t for t in tags.split(",") if "x_transferred" not in t
                    )
                    if clean_tags:
                        lines.append(f"- {url} ({clean_tags})")
                    else:
                        lines.append(f"- {url}")
                else:
                    lines.append(f"- {url}")

        markdown_output = "\n".join(lines)
        if output:
            from pathlib import Path

            Path(output).write_text(markdown_output)
            console.print(f"[green]Output written to {output}[/green]")
        else:
            print(markdown_output)

    else:
        title = row.get("cna_title") or "(No title)"
        console.print(
            Panel(
                f"[bold cyan]{row.get('cve_id')}[/bold cyan]\n\n"
                f"[bold]State:[/bold] {row.get('state')}\n"
                f"[bold]Title:[/bold] {title}\n"
                f"[bold]Published:[/bold] {row.get('date_published')}\n"
                f"[bold]Updated:[/bold] {row.get('date_updated')}",
                title="CVE Details",
            )
        )

        if best_metric:
            score = best_metric.get("base_score")
            if score:
                color = "red" if score >= 7.0 else "yellow" if score >= 4.0 else "green"
                metric_type = best_metric.get("metric_type", "")
                source = best_metric.get("source", "cna")
                source_label = "" if source == "cna" else f" (from {source})"
                console.print(
                    f"\n[bold]CVSS Score:[/bold] [{color}]{score:.1f}[/{color}] ({metric_type}){source_label}"
                )

        if description:
            console.print(Panel(description, title="Description"))

        # Show detailed CVSS metrics in verbose mode (after description)
        if verbose and best_metric:
            score = best_metric.get("base_score")
            metric_type = best_metric.get("metric_type", "")

            if score or best_metric.get("base_severity"):
                cvss_details = []

                vector = best_metric.get("vector_string")
                severity = best_metric.get("base_severity")

                if vector:
                    cvss_details.append(f"[bold]Vector:[/bold] {vector}")
                if severity:
                    cvss_details.append(f"[bold]Severity:[/bold] {severity}")

                # Show CVSS v3.x/v4 specific metrics
                if metric_type.startswith("cvssV3") or metric_type.startswith("cvssV4"):
                    cvss_details.append("")  # Empty line for spacing

                    av = best_metric.get("attack_vector")
                    if av:
                        cvss_details.append(f"[dim]Attack Vector:[/dim] {av}")

                    ac = best_metric.get("attack_complexity")
                    if ac:
                        cvss_details.append(f"[dim]Attack Complexity:[/dim] {ac}")

                    pr = best_metric.get("privileges_required")
                    if pr:
                        cvss_details.append(f"[dim]Privileges Required:[/dim] {pr}")

                    ui = best_metric.get("user_interaction")
                    if ui:
                        cvss_details.append(f"[dim]User Interaction:[/dim] {ui}")

                    scope = best_metric.get("scope")
                    if scope:
                        cvss_details.append(f"[dim]Scope:[/dim] {scope}")

                    cvss_details.append("")  # Empty line for spacing

                    c = best_metric.get("confidentiality_impact")
                    if c:
                        cvss_details.append(f"[dim]Confidentiality Impact:[/dim] {c}")

                    i = best_metric.get("integrity_impact")
                    if i:
                        cvss_details.append(f"[dim]Integrity Impact:[/dim] {i}")

                    a = best_metric.get("availability_impact")
                    if a:
                        cvss_details.append(f"[dim]Availability Impact:[/dim] {a}")

                    # CVSS v4 additional metrics
                    if metric_type.startswith("cvssV4"):
                        ar = best_metric.get("attack_requirements")
                        if ar:
                            cvss_details.append(f"[dim]Attack Requirements:[/dim] {ar}")

                # Show CVSS v2 specific metrics
                elif metric_type == "cvssV2":
                    cvss_details.append("")  # Empty line for spacing

                    av = best_metric.get("access_vector")
                    if av:
                        cvss_details.append(f"[dim]Access Vector:[/dim] {av}")

                    ac = best_metric.get("access_complexity")
                    if ac:
                        cvss_details.append(f"[dim]Access Complexity:[/dim] {ac}")

                    auth = best_metric.get("authentication")
                    if auth:
                        cvss_details.append(f"[dim]Authentication:[/dim] {auth}")

                    cvss_details.append("")  # Empty line for spacing

                    c = best_metric.get("confidentiality_impact")
                    if c:
                        cvss_details.append(f"[dim]Confidentiality Impact:[/dim] {c}")

                    i = best_metric.get("integrity_impact")
                    if i:
                        cvss_details.append(f"[dim]Integrity Impact:[/dim] {i}")

                    a = best_metric.get("availability_impact")
                    if a:
                        cvss_details.append(f"[dim]Availability Impact:[/dim] {a}")

                if cvss_details:
                    console.print(Panel("\n".join(cvss_details), title="CVSS Details"))

        # Show KEV info if present
        if kev_info:
            date_added = kev_info.get("dateAdded", "Unknown")
            console.print(
                Panel(
                    f"[bold red]⚠️ This CVE is in CISA's Known Exploited Vulnerabilities catalog[/bold red]\n\n"
                    f"[bold]Date Added:[/bold] {date_added}",
                    title="Known Exploited Vulnerability",
                    border_style="red",
                )
            )

        # Show SSVC info if present and verbose
        if ssvc_info and verbose:
            ssvc_details = []
            options = ssvc_info.get("options", [])
            for opt in options:
                for key, value in opt.items():
                    ssvc_details.append(f"[bold]{key}:[/bold] {value}")
            if ssvc_details:
                console.print(Panel("\n".join(ssvc_details), title="SSVC Assessment"))

        if result.products is not None and len(result.products) > 0:
            table = Table(title="Affected Products")
            table.add_column("Vendor")
            table.add_column("Product")
            table.add_column("Package")
            table.add_column("Default Status")
            for prod in result.products.iter_rows(named=True):
                table.add_row(
                    prod.get("vendor", ""),
                    prod.get("product", ""),
                    prod.get("package_name", ""),
                    prod.get("default_status", ""),
                )
            console.print(table)

        if result.versions is not None and len(result.versions) > 0 and verbose:
            table = Table(title="Affected Versions")
            table.add_column("Version")
            table.add_column("Type")
            table.add_column("Status")
            table.add_column("Less Than")
            for ver in result.versions.iter_rows(named=True):
                table.add_row(
                    ver.get("version", ""),
                    ver.get("version_type", ""),
                    ver.get("status", ""),
                    ver.get("less_than", "") or ver.get("less_than_or_equal", ""),
                )
            console.print(table)

        if result.cwes is not None and len(result.cwes) > 0:
            console.print("\n[bold]CWEs:[/bold]")
            for cwe in result.cwes.iter_rows(named=True):
                cwe_id = cwe.get("cwe_id")
                cwe_desc = cwe.get("description", "")[:80]
                # Handle missing CWE IDs
                if cwe_id:
                    console.print(f"  - {cwe_id}: {cwe_desc}")
                elif cwe_desc:
                    console.print(f"  - [dim](No CWE ID):[/dim] {cwe_desc}")

        if unique_refs and verbose:
            console.print("\n[bold]References:[/bold]")
            for ref in unique_refs:
                url = ref.get("url", "")
                console.print(f"  - {url}")


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
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed output"),
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

    _output_result(
        result,
        format=format,
        verbose=verbose,
        limit=limit,
        search_service=service,
        output_file=output,
    )


def main() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    main()
