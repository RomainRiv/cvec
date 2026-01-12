"""Output formatters for cvec CLI.

This module provides formatting utilities for displaying search results
in various formats (table, JSON, markdown) with rich console output.
It decouples display logic from search/command logic.
"""

import json
from typing import Any, Optional, TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from cvec.services.search import CVESearchService, SearchResult


console = Console()


class OutputFormat:
    """Output format constants."""
    
    JSON = "json"
    TABLE = "table"
    MARKDOWN = "markdown"


def get_severity_color(score: Optional[float]) -> str:
    """Get the Rich color for a severity score.
    
    Args:
        score: CVSS score (0-10).
    
    Returns:
        Color name for Rich formatting.
    """
    if score is None:
        return "dim"
    if score >= 9.0:
        return "red bold"
    if score >= 7.0:
        return "red"
    if score >= 4.0:
        return "yellow"
    return "green"


def get_severity_info(
    row: dict, search_service: Optional["CVESearchService"] = None
) -> tuple[str, str, Optional[float]]:
    """Get severity score, version, and numeric score from a CVE row.

    Returns a tuple of (score_str, version_str, numeric_score).
    - score_str: "8.1" or "High" or "-"
    - version_str: "v3.1", "v4.0*", "text", or "-"
    - numeric_score: Float score or None

    ADP scores are marked with * (e.g., "v3.1*").
    """
    cve_id = row.get("cve_id", "")
    
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
                return f"{score:.1f}", version, float(score)
            elif base_severity:
                # Text severity only (no numeric score)
                return str(base_severity), "text", None

    return "-", "-", None


def truncate_text(text: str, max_length: int = 80) -> str:
    """Truncate text with ellipsis if needed.
    
    Args:
        text: Text to truncate.
        max_length: Maximum length including ellipsis.
    
    Returns:
        Truncated text.
    """
    if len(text) <= max_length:
        return text
    return text[: max_length - 3] + "..."


def format_similarity_score(score: Optional[float]) -> str:
    """Format a similarity score for display.
    
    Args:
        score: Similarity score (0-1).
    
    Returns:
        Formatted score string.
    """
    if score is None:
        return "-"
    return f"{score:.2f}"


def _build_cve_record(
    row: dict,
    search_service: Optional["CVESearchService"] = None,
    include_description: bool = False,
) -> dict:
    """Build a CVE record dictionary for JSON output.
    
    Args:
        row: Raw row from DataFrame.
        search_service: Service for getting additional info.
        include_description: Whether to include description.
    
    Returns:
        Enhanced record dictionary.
    """
    record = dict(row)
    
    if search_service:
        severity, version, _ = get_severity_info(row, search_service)
        record["severity"] = severity
        record["cvss_version"] = version
        
        if include_description:
            cve_id = row.get("cve_id", "")
            description = search_service.get_description(cve_id)
            if description:
                record["description"] = description
    
    return record


def output_search_results_json(
    result: "SearchResult",
    verbose: bool = False,
    limit: int = 100,
    search_service: Optional["CVESearchService"] = None,
    output_file: Optional[str] = None,
    include_description: bool = True,
) -> None:
    """Output search results as JSON.
    
    Args:
        result: Search results to output.
        verbose: Include summary statistics.
        limit: Maximum results (ignored with output_file).
        search_service: Service for additional info.
        output_file: Path to write output.
        include_description: Include CVE descriptions.
    """
    df = result.cves
    total_count = len(df)
    
    truncated = False if output_file else len(df) > limit
    if truncated:
        df = df.head(limit)
    
    records = []
    for row in df.iter_rows(named=True):
        record = _build_cve_record(
            row, search_service, include_description=include_description
        )
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


def output_search_results_markdown(
    result: "SearchResult",
    verbose: bool = False,
    limit: int = 100,
    search_service: Optional["CVESearchService"] = None,
    output_file: Optional[str] = None,
    include_description: bool = True,
) -> None:
    """Output search results as Markdown.
    
    Args:
        result: Search results to output.
        verbose: Include summary statistics.
        limit: Maximum results (ignored with output_file).
        search_service: Service for additional info.
        output_file: Path to write output.
        include_description: Include CVE descriptions.
    """
    df = result.cves
    total_count = len(df)
    
    truncated = False if output_file else len(df) > limit
    if truncated:
        df = df.head(limit)
    
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
    
    for row in df.iter_rows(named=True):
        cve_id = row.get("cve_id", "")
        state = row.get("state", "")
        title = row.get("cna_title") or "(No title)"
        severity, version, _ = get_severity_info(row, search_service)
        
        # Check for similarity score in row
        similarity = row.get("similarity_score")
        match_info = f" (match: {similarity:.2f})" if similarity else ""
        
        lines.append(f"### {cve_id}{match_info}\n")
        lines.append(f"**State:** {state} | **Severity:** {severity} ({version})\n")
        lines.append(f"**Title:** {title}\n")
        
        if include_description and search_service:
            description = search_service.get_description(cve_id)
            if description:
                # Truncate for markdown if very long
                if len(description) > 500:
                    description = description[:500] + "..."
                lines.append(f"\n{description}\n")
        
        lines.append("")
    
    markdown_output = "\n".join(lines)
    
    if output_file:
        from pathlib import Path
        Path(output_file).write_text(markdown_output)
        console.print(f"[green]Output written to {output_file}[/green]")
    else:
        print(markdown_output)


def output_search_results_table(
    result: "SearchResult",
    verbose: bool = False,
    limit: int = 100,
    search_service: Optional["CVESearchService"] = None,
    compact: bool = False,
    show_description: bool = True,
) -> None:
    """Output search results as a Rich table.
    
    Args:
        result: Search results to output.
        verbose: Show summary statistics.
        limit: Maximum results to show.
        search_service: Service for additional info.
        compact: Use compact format (default).
        show_description: Show descriptions (when compact=False).
    """
    df = result.cves
    total_count = len(df)
    
    if total_count == 0:
        console.print("[yellow]No results found.[/yellow]")
        return
    
    truncated = len(df) > limit
    if truncated:
        df = df.head(limit)
        console.print(
            f"[yellow]Showing first {limit} of {total_count} results[/yellow]"
        )
    
    # Check if we have similarity scores
    has_similarity = "similarity_score" in df.columns
    
    table = Table(title=f"CVE Results ({total_count} total)")
    table.add_column("CVE ID", style="cyan", no_wrap=True)
    
    if has_similarity:
        table.add_column("Match", justify="center", style="magenta")
    
    table.add_column("Severity", justify="right")
    table.add_column("Ver", justify="center", style="dim")
    table.add_column("Title")
    table.add_column("Published", style="dim")
    
    for row in df.iter_rows(named=True):
        cve_id = row.get("cve_id", "")
        title = truncate_text(row.get("cna_title") or "", 55)
        severity, version, score = get_severity_info(row, search_service)
        published = str(row.get("date_published") or "")[:10]
        
        # Format severity with color
        severity_text = Text(severity)
        severity_text.stylize(get_severity_color(score))
        
        row_data = [cve_id]
        
        if has_similarity:
            sim_score = row.get("similarity_score")
            row_data.append(format_similarity_score(sim_score))
        
        row_data.extend([severity_text, version, title, published])
        table.add_row(*row_data)
    
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


def output_search_results_detailed(
    result: "SearchResult",
    limit: int = 10,
    search_service: Optional["CVESearchService"] = None,
) -> None:
    """Output search results with detailed CVE information.
    
    This shows each CVE with description and key details,
    similar to 'cvec get' but more compact for multiple results.
    
    Args:
        result: Search results to output.
        limit: Maximum results to show.
        search_service: Service for additional info.
    """
    df = result.cves
    total_count = len(df)
    
    if total_count == 0:
        console.print("[yellow]No results found.[/yellow]")
        return
    
    truncated = len(df) > limit
    if truncated:
        df = df.head(limit)
        console.print(
            f"[yellow]Showing first {limit} of {total_count} results (use -n to show more)[/yellow]\n"
        )
    
    # Check if we have similarity scores
    has_similarity = "similarity_score" in df.columns
    
    for i, row in enumerate(df.iter_rows(named=True)):
        if i > 0:
            console.print()  # Separator between CVEs
        
        cve_id = row.get("cve_id", "")
        state = row.get("state", "")
        title = row.get("cna_title") or "(No title)"
        published = str(row.get("date_published") or "")[:10]
        
        # Get severity info
        severity, version, score = get_severity_info(row, search_service)
        severity_color = get_severity_color(score)
        
        # Build header line
        header_parts = [f"[bold cyan]{cve_id}[/bold cyan]"]
        
        if has_similarity:
            sim_score = row.get("similarity_score")
            if sim_score:
                header_parts.append(f"[magenta](match: {sim_score:.2f})[/magenta]")
        
        header_parts.append(f"[{severity_color}]{severity}[/{severity_color}]")
        header_parts.append(f"[dim]({version})[/dim]")
        header_parts.append(f"[dim]{state}[/dim]")
        
        console.print(" | ".join(header_parts))
        console.print(f"[bold]{title}[/bold]")
        console.print(f"[dim]Published: {published}[/dim]")
        
        # Get and display description
        if search_service:
            description = search_service.get_description(cve_id)
            if description:
                # Truncate very long descriptions
                if len(description) > 300:
                    description = description[:300] + "..."
                console.print(f"[italic]{description}[/italic]")
            
            # Show affected products (brief)
            if result.products is not None and len(result.products) > 0:
                import polars as pl
                cve_products = result.products.filter(pl.col("cve_id") == cve_id)
                if len(cve_products) > 0:
                    products_list = []
                    for prod in cve_products.head(3).iter_rows(named=True):
                        vendor = prod.get("vendor", "")
                        product = prod.get("product", "")
                        if vendor and product:
                            products_list.append(f"{vendor}/{product}")
                        elif product:
                            products_list.append(product)
                    if products_list:
                        more = f" (+{len(cve_products) - 3} more)" if len(cve_products) > 3 else ""
                        console.print(f"[dim]Products: {', '.join(products_list)}{more}[/dim]")
            
            # Show CWEs (brief)
            if result.cwes is not None and len(result.cwes) > 0:
                import polars as pl
                cve_cwes = result.cwes.filter(pl.col("cve_id") == cve_id)
                if len(cve_cwes) > 0:
                    cwes_list = [
                        cwe.get("cwe_id", "") 
                        for cwe in cve_cwes.head(3).iter_rows(named=True)
                        if cwe.get("cwe_id")
                    ]
                    if cwes_list:
                        console.print(f"[dim]CWEs: {', '.join(cwes_list)}[/dim]")


def output_search_results(
    result: "SearchResult",
    format: str = OutputFormat.TABLE,
    verbose: bool = False,
    limit: int = 100,
    search_service: Optional["CVESearchService"] = None,
    output_file: Optional[str] = None,
    detailed: bool = False,
) -> None:
    """Output search results in the specified format.

    Args:
        result: Search results to output.
        format: Output format (table, json, markdown).
        verbose: Include detailed information.
        limit: Maximum number of results (ignored for file output).
        search_service: Service for getting severity info.
        output_file: Path to write output file (if specified, no truncation).
        detailed: Show detailed output with descriptions (table format only).
    """
    if len(result.cves) == 0:
        if output_file:
            # Still write empty result to file
            pass
        else:
            console.print("[yellow]No results found.[/yellow]")
            return

    # When writing to file, don't truncate
    file_limit = 10000 if output_file else limit

    if format == OutputFormat.JSON:
        output_search_results_json(
            result,
            verbose=verbose,
            limit=file_limit,
            search_service=search_service,
            output_file=output_file,
            include_description=True,
        )
    elif format == OutputFormat.MARKDOWN:
        output_search_results_markdown(
            result,
            verbose=verbose,
            limit=file_limit,
            search_service=search_service,
            output_file=output_file,
            include_description=True,
        )
    else:
        # Table format
        if output_file:
            # For file output with table format, use markdown instead
            output_search_results_markdown(
                result,
                verbose=verbose,
                limit=file_limit,
                search_service=search_service,
                output_file=output_file,
                include_description=True,
            )
        elif detailed:
            output_search_results_detailed(
                result,
                limit=limit,
                search_service=search_service,
            )
        else:
            output_search_results_table(
                result,
                verbose=verbose,
                limit=limit,
                search_service=search_service,
            )


def output_cve_detail(
    row: dict,
    result: "SearchResult",
    search_service: "CVESearchService",
    format: str = OutputFormat.TABLE,
    verbose: bool = False,
    output_file: Optional[str] = None,
) -> None:
    """Output detailed CVE information.
    
    Args:
        row: CVE row data.
        result: Full search result with related data.
        search_service: Service for additional info.
        format: Output format.
        verbose: Show all available details.
        output_file: Path to write output.
    """
    cve_id = row.get("cve_id", "")
    description = search_service.get_description(cve_id)
    best_metric = search_service.get_best_metric(cve_id)
    kev_info = search_service.get_kev_info(cve_id)
    ssvc_info = search_service.get_ssvc_info(cve_id)
    
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
        _output_cve_detail_json(
            row, result, description, best_metric, kev_info, ssvc_info,
            unique_refs, output_file
        )
    elif format == OutputFormat.MARKDOWN:
        _output_cve_detail_markdown(
            row, result, description, best_metric, kev_info,
            unique_refs, output_file
        )
    else:
        _output_cve_detail_table(
            row, result, description, best_metric, kev_info, ssvc_info,
            unique_refs, verbose
        )


def _output_cve_detail_json(
    row: dict,
    result: "SearchResult",
    description: Optional[str],
    best_metric: Optional[dict],
    kev_info: Optional[dict],
    ssvc_info: Optional[dict],
    unique_refs: list[dict],
    output_file: Optional[str],
) -> None:
    """Output CVE detail as JSON."""
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
    
    if output_file:
        from pathlib import Path
        Path(output_file).write_text(json_output)
        console.print(f"[green]Output written to {output_file}[/green]")
    else:
        print(json_output)


def _output_cve_detail_markdown(
    row: dict,
    result: "SearchResult",
    description: Optional[str],
    best_metric: Optional[dict],
    kev_info: Optional[dict],
    unique_refs: list[dict],
    output_file: Optional[str],
) -> None:
    """Output CVE detail as Markdown."""
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
            if cwe_id:
                lines.append(f"- {cwe_id}: {cwe_desc}")
            elif cwe_desc:
                lines.append(f"- (No CWE ID): {cwe_desc}")
    
    if unique_refs:
        lines.append("\n## References\n")
        for ref in unique_refs:
            url = ref.get("url", "")
            tags = ref.get("tags", "")
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
    
    if output_file:
        from pathlib import Path
        Path(output_file).write_text(markdown_output)
        console.print(f"[green]Output written to {output_file}[/green]")
    else:
        print(markdown_output)


def _output_cve_detail_table(
    row: dict,
    result: "SearchResult",
    description: Optional[str],
    best_metric: Optional[dict],
    kev_info: Optional[dict],
    ssvc_info: Optional[dict],
    unique_refs: list[dict],
    verbose: bool,
) -> None:
    """Output CVE detail as Rich table/panels."""
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
    
    # Show detailed CVSS metrics in verbose mode
    if verbose and best_metric:
        _output_cvss_details(best_metric)
    
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
    
    # Show affected products
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
    
    # Show affected versions in verbose mode
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
    
    # Show CWEs
    if result.cwes is not None and len(result.cwes) > 0:
        console.print("\n[bold]CWEs:[/bold]")
        for cwe in result.cwes.iter_rows(named=True):
            cwe_id = cwe.get("cwe_id")
            cwe_desc = cwe.get("description", "")[:80]
            if cwe_id:
                console.print(f"  - {cwe_id}: {cwe_desc}")
            elif cwe_desc:
                console.print(f"  - [dim](No CWE ID):[/dim] {cwe_desc}")
    
    # Show references in verbose mode
    if unique_refs and verbose:
        console.print("\n[bold]References:[/bold]")
        for ref in unique_refs:
            url = ref.get("url", "")
            console.print(f"  - {url}")


def _output_cvss_details(best_metric: dict) -> None:
    """Output CVSS metric details."""
    score = best_metric.get("base_score")
    metric_type = best_metric.get("metric_type", "")
    
    if not (score or best_metric.get("base_severity")):
        return
    
    cvss_details = []
    vector = best_metric.get("vector_string")
    severity = best_metric.get("base_severity")
    
    if vector:
        cvss_details.append(f"[bold]Vector:[/bold] {vector}")
    if severity:
        cvss_details.append(f"[bold]Severity:[/bold] {severity}")
    
    # Show CVSS v3.x/v4 specific metrics
    if metric_type.startswith("cvssV3") or metric_type.startswith("cvssV4"):
        cvss_details.append("")
        
        fields = [
            ("attack_vector", "Attack Vector"),
            ("attack_complexity", "Attack Complexity"),
            ("privileges_required", "Privileges Required"),
            ("user_interaction", "User Interaction"),
            ("scope", "Scope"),
        ]
        
        for field, label in fields:
            value = best_metric.get(field)
            if value:
                cvss_details.append(f"[dim]{label}:[/dim] {value}")
        
        cvss_details.append("")
        
        impact_fields = [
            ("confidentiality_impact", "Confidentiality Impact"),
            ("integrity_impact", "Integrity Impact"),
            ("availability_impact", "Availability Impact"),
        ]
        
        for field, label in impact_fields:
            value = best_metric.get(field)
            if value:
                cvss_details.append(f"[dim]{label}:[/dim] {value}")
        
        # CVSS v4 additional metrics
        if metric_type.startswith("cvssV4"):
            ar = best_metric.get("attack_requirements")
            if ar:
                cvss_details.append(f"[dim]Attack Requirements:[/dim] {ar}")
    
    # Show CVSS v2 specific metrics
    elif metric_type == "cvssV2":
        cvss_details.append("")
        
        fields = [
            ("access_vector", "Access Vector"),
            ("access_complexity", "Access Complexity"),
            ("authentication", "Authentication"),
        ]
        
        for field, label in fields:
            value = best_metric.get(field)
            if value:
                cvss_details.append(f"[dim]{label}:[/dim] {value}")
        
        cvss_details.append("")
        
        impact_fields = [
            ("confidentiality_impact", "Confidentiality Impact"),
            ("integrity_impact", "Integrity Impact"),
            ("availability_impact", "Availability Impact"),
        ]
        
        for field, label in impact_fields:
            value = best_metric.get(field)
            if value:
                cvss_details.append(f"[dim]{label}:[/dim] {value}")
    
    if cvss_details:
        console.print(Panel("\n".join(cvss_details), title="CVSS Details"))


def output_products_table(
    products: Any,  # polars DataFrame
    limit: int = 100,
    format: str = OutputFormat.TABLE,
    output_file: Optional[str] = None,
) -> None:
    """Output products search results.
    
    Args:
        products: DataFrame of products.
        limit: Maximum results to show.
        format: Output format.
        output_file: Path to write output.
    """
    total_count = len(products)
    
    if total_count == 0:
        console.print("[yellow]No products found.[/yellow]")
        return
    
    truncated = False if output_file else len(products) > limit
    if truncated:
        products = products.head(limit)
    
    if format == OutputFormat.JSON:
        records = products.to_dicts()
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
        lines = ["# Product Search Results\n"]
        lines.append(f"Found **{total_count}** products\n")
        lines.append("| Vendor | Product | CVE Count |")
        lines.append("|--------|---------|-----------|")
        
        for row in products.iter_rows(named=True):
            vendor = row.get("vendor", "")
            product = row.get("product", "")
            count = row.get("cve_count", "")
            lines.append(f"| {vendor} | {product} | {count} |")
        
        markdown_output = "\n".join(lines)
        
        if output_file:
            from pathlib import Path
            Path(output_file).write_text(markdown_output)
            console.print(f"[green]Output written to {output_file}[/green]")
        else:
            print(markdown_output)
    
    else:
        if truncated:
            console.print(
                f"[yellow]Showing first {limit} of {total_count} results[/yellow]"
            )
        
        table = Table(title=f"Products ({total_count} total)")
        table.add_column("Vendor", style="cyan")
        table.add_column("Product", style="green")
        table.add_column("CVE Count", justify="right")
        table.add_column("Package", style="dim")
        
        for row in products.iter_rows(named=True):
            table.add_row(
                row.get("vendor", ""),
                row.get("product", ""),
                str(row.get("cve_count", "")),
                row.get("package_name", "") or "",
            )
        
        console.print(table)
