"""CVE search service.

This service provides search capabilities over the normalized CVE parquet files.
It supports searching by CVE ID, product, vendor, CWE, severity, date range,
and semantic similarity using embeddings.
"""

import re
from datetime import datetime, timedelta
from typing import Any, Dict, List, Literal, Optional

import polars as pl

from cvec.core.config import Config, get_config

# Severity levels based on CVSS scores
SEVERITY_THRESHOLDS = {
    "none": (0.0, 0.0),
    "low": (0.1, 3.9),
    "medium": (4.0, 6.9),
    "high": (7.0, 8.9),
    "critical": (9.0, 10.0),
}

SeverityLevel = Literal["none", "low", "medium", "high", "critical"]


class SearchResult:
    """Container for search results with metadata."""

    def __init__(
        self,
        cves: pl.DataFrame,
        descriptions: Optional[pl.DataFrame] = None,
        metrics: Optional[pl.DataFrame] = None,
        products: Optional[pl.DataFrame] = None,
        versions: Optional[pl.DataFrame] = None,
        cwes: Optional[pl.DataFrame] = None,
        references: Optional[pl.DataFrame] = None,
        credits: Optional[pl.DataFrame] = None,
    ):
        self.cves = cves
        self.descriptions = descriptions
        self.metrics = metrics
        self.products = products
        self.versions = versions
        self.cwes = cwes
        self.references = references
        self.credits = credits

    @property
    def count(self) -> int:
        """Number of CVE results."""
        return len(self.cves)

    def to_dicts(self) -> List[dict]:
        """Convert results to list of dictionaries."""
        return self.cves.to_dicts()

    def to_json(self) -> str:
        """Convert results to JSON string."""
        return self.cves.write_json()

    def summary(self) -> dict:
        """Get a summary of the search results."""
        if self.count == 0:
            return {"count": 0, "cves": []}

        return {
            "count": self.count,
            "severity_distribution": self._get_severity_distribution(),
            "year_distribution": self._get_year_distribution(),
        }

    def _get_severity_distribution(self) -> dict:
        """Get count of CVEs by severity based on metrics."""
        result = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "none": 0,
            "unknown": 0,
        }

        if self.metrics is None or len(self.metrics) == 0:
            result["unknown"] = self.count
            return result

        # Get best score per CVE from metrics
        cve_ids = set(self.cves.get_column("cve_id").to_list())

        # Filter metrics for our CVEs and get best score per CVE
        relevant_metrics = self.metrics.filter(
            pl.col("cve_id").is_in(cve_ids)
            & pl.col("base_score").is_not_null()
            & pl.col("metric_type").str.starts_with("cvss")
        )

        if len(relevant_metrics) == 0:
            result["unknown"] = self.count
            return result

        # Preference order for metrics (prefer CNA over ADP, prefer newer versions)
        best_scores = (
            relevant_metrics.with_columns(
                [
                    # Score metrics by preference (higher = better)
                    pl.when(pl.col("source") == "cna")
                    .then(100)
                    .otherwise(0)
                    .alias("source_pref"),
                    pl.when(pl.col("metric_type") == "cvssV4_0")
                    .then(40)
                    .when(pl.col("metric_type") == "cvssV3_1")
                    .then(30)
                    .when(pl.col("metric_type") == "cvssV3_0")
                    .then(20)
                    .otherwise(10)
                    .alias("version_pref"),
                ]
            )
            .with_columns(
                [(pl.col("source_pref") + pl.col("version_pref")).alias("preference")]
            )
            .sort(["cve_id", "preference"], descending=[False, True])
            .group_by("cve_id")
            .first()
        )

        cves_with_scores = set(best_scores.get_column("cve_id").to_list())

        for row in best_scores.iter_rows(named=True):
            score = row.get("base_score")
            if score is None:
                result["unknown"] += 1
            elif score >= 9.0:
                result["critical"] += 1
            elif score >= 7.0:
                result["high"] += 1
            elif score >= 4.0:
                result["medium"] += 1
            elif score >= 0.1:
                result["low"] += 1
            else:
                result["none"] += 1

        # Count CVEs without any score
        result["unknown"] += len(cve_ids - cves_with_scores)

        return result

    def _get_year_distribution(self) -> dict[str, int]:
        """Get count of CVEs by year."""
        result: dict[str, int] = {}
        for row in self.cves.iter_rows(named=True):
            cve_id = row.get("cve_id", "")
            if cve_id.startswith("CVE-"):
                parts = cve_id.split("-")
                if len(parts) >= 2:
                    year = parts[1]
                    result[year] = result.get(year, 0) + 1
        return dict(sorted(result.items()))


class CVESearchService:
    """Service for searching CVE data."""

    def __init__(self, config: Optional[Config] = None):
        """Initialize the search service.

        Args:
            config: Configuration instance. Uses default if not provided.
        """
        self.config = config or get_config()
        self._cves_df: Optional[pl.DataFrame] = None
        self._descriptions_df: Optional[pl.DataFrame] = None
        self._metrics_df: Optional[pl.DataFrame] = None
        self._products_df: Optional[pl.DataFrame] = None
        self._versions_df: Optional[pl.DataFrame] = None
        self._cwes_df: Optional[pl.DataFrame] = None
        self._references_df: Optional[pl.DataFrame] = None
        self._credits_df: Optional[pl.DataFrame] = None

    def _load_data(self) -> None:
        """Load data from Parquet files if not already loaded."""
        if self._cves_df is None:
            cves_path = self.config.cves_parquet
            if not cves_path.exists():
                raise FileNotFoundError(
                    f"CVE data not found at {cves_path}. Run 'cvec db update' or 'cvec db build extract-parquet' first."
                )
            self._cves_df = pl.read_parquet(cves_path)

        if self._descriptions_df is None:
            desc_path = self.config.cve_descriptions_parquet
            if desc_path.exists():
                self._descriptions_df = pl.read_parquet(desc_path)

        if self._metrics_df is None:
            metrics_path = self.config.cve_metrics_parquet
            if metrics_path.exists():
                self._metrics_df = pl.read_parquet(metrics_path)

        if self._products_df is None:
            products_path = self.config.cve_products_parquet
            if products_path.exists():
                self._products_df = pl.read_parquet(products_path)

        if self._versions_df is None:
            versions_path = self.config.cve_versions_parquet
            if versions_path.exists():
                self._versions_df = pl.read_parquet(versions_path)

        if self._cwes_df is None:
            cwe_path = self.config.cve_cwes_parquet
            if cwe_path.exists():
                self._cwes_df = pl.read_parquet(cwe_path)

        if self._references_df is None:
            refs_path = self.config.cve_references_parquet
            if refs_path.exists():
                self._references_df = pl.read_parquet(refs_path)

        if self._credits_df is None:
            credits_path = self.config.cve_credits_parquet
            if credits_path.exists():
                self._credits_df = pl.read_parquet(credits_path)

    def _ensure_cves_loaded(self) -> pl.DataFrame:
        """Load data and return CVEs dataframe (guaranteed non-None)."""
        self._load_data()
        assert self._cves_df is not None
        return self._cves_df

    def _get_related_data(
        self, cve_ids: List[str]
    ) -> Dict[str, Optional[pl.DataFrame]]:
        """Get all related data for a set of CVE IDs."""
        result: Dict[str, Optional[pl.DataFrame]] = {
            "descriptions": None,
            "metrics": None,
            "products": None,
            "versions": None,
            "cwes": None,
            "references": None,
            "credits": None,
        }

        if not cve_ids:
            return result

        cve_id_set = set(cve_ids)

        if self._descriptions_df is not None:
            result["descriptions"] = self._descriptions_df.filter(
                pl.col("cve_id").is_in(cve_id_set)
            )

        if self._metrics_df is not None:
            result["metrics"] = self._metrics_df.filter(
                pl.col("cve_id").is_in(cve_id_set)
            )

        if self._products_df is not None:
            result["products"] = self._products_df.filter(
                pl.col("cve_id").is_in(cve_id_set)
            )

        if self._versions_df is not None:
            result["versions"] = self._versions_df.filter(
                pl.col("cve_id").is_in(cve_id_set)
            )

        if self._cwes_df is not None:
            result["cwes"] = self._cwes_df.filter(pl.col("cve_id").is_in(cve_id_set))

        if self._references_df is not None:
            result["references"] = self._references_df.filter(
                pl.col("cve_id").is_in(cve_id_set)
            )

        if self._credits_df is not None:
            result["credits"] = self._credits_df.filter(
                pl.col("cve_id").is_in(cve_id_set)
            )

        return result

    def by_id(self, cve_id: str) -> SearchResult:
        """Search for a specific CVE by ID.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234").

        Returns:
            SearchResult with matching CVE(s).
        """
        cves_df = self._ensure_cves_loaded()

        # Normalize ID
        cve_id = cve_id.upper()
        if not cve_id.startswith("CVE-"):
            cve_id = f"CVE-{cve_id}"

        result = cves_df.filter(pl.col("cve_id") == cve_id)
        result = result.sort("date_published", descending=True)
        cve_ids = result.get_column("cve_id").to_list()
        related = self._get_related_data(cve_ids)

        return SearchResult(result, **related)

    def by_product(
        self,
        product: str,
        vendor: Optional[str] = None,
        fuzzy: bool = True,
        exact: bool = False,
    ) -> SearchResult:
        """Search CVEs affecting a product.

        Args:
            product: Product name to search for.
            vendor: Optional vendor name to filter by.
            fuzzy: If True, use case-insensitive substring matching.
            exact: If True, use literal string matching (no regex).

        Returns:
            SearchResult with matching CVEs.
        """
        cves_df = self._ensure_cves_loaded()

        if self._products_df is None:
            return SearchResult(pl.DataFrame(schema=cves_df.schema))

        # Filter products
        if fuzzy:
            # When exact=True, use literal matching (no regex)
            # When exact=False, use regex matching (escape special chars for safety)
            if exact:
                search_product = product.lower()
            else:
                search_product = re.escape(product.lower())
            product_filter = (
                pl.col("product")
                .str.to_lowercase()
                .str.contains(search_product, literal=exact)
            )
        else:
            product_filter = pl.col("product") == product

        if vendor:
            if fuzzy:
                if exact:
                    search_vendor = vendor.lower()
                else:
                    search_vendor = re.escape(vendor.lower())
                vendor_filter = (
                    pl.col("vendor")
                    .str.to_lowercase()
                    .str.contains(search_vendor, literal=exact)
                )
            else:
                vendor_filter = pl.col("vendor") == vendor
            product_filter = product_filter & vendor_filter

        matching_products = self._products_df.filter(product_filter)
        cve_ids = matching_products.get_column("cve_id").unique().to_list()

        # Get CVE details
        result = cves_df.filter(pl.col("cve_id").is_in(cve_ids))
        result = result.sort("date_published", descending=True)
        related = self._get_related_data(cve_ids)

        return SearchResult(result, **related)

    def by_vendor(
        self, vendor: str, fuzzy: bool = True, exact: bool = False
    ) -> SearchResult:
        """Search CVEs affecting products from a vendor.

        Args:
            vendor: Vendor name to search for.
            fuzzy: If True, use case-insensitive substring matching.
            exact: If True, use literal string matching (no regex).

        Returns:
            SearchResult with matching CVEs.
        """
        cves_df = self._ensure_cves_loaded()

        if self._products_df is None:
            return SearchResult(pl.DataFrame(schema=cves_df.schema))

        if fuzzy:
            # When exact=True, use literal matching (no regex)
            # When exact=False, use regex matching (escape special chars for safety)
            if exact:
                search_vendor = vendor.lower()
            else:
                search_vendor = re.escape(vendor.lower())
            vendor_filter = (
                pl.col("vendor")
                .str.to_lowercase()
                .str.contains(search_vendor, literal=exact)
            )
        else:
            vendor_filter = pl.col("vendor") == vendor

        matching_products = self._products_df.filter(vendor_filter)
        cve_ids = matching_products.get_column("cve_id").unique().to_list()

        result = cves_df.filter(pl.col("cve_id").is_in(cve_ids))
        result = result.sort("date_published", descending=True)
        related = self._get_related_data(cve_ids)

        return SearchResult(result, **related)

    def by_cwe(self, cwe_id: str) -> SearchResult:
        """Search CVEs by CWE identifier.

        Args:
            cwe_id: CWE identifier (e.g., "CWE-79" or "79").

        Returns:
            SearchResult with matching CVEs.
        """
        cves_df = self._ensure_cves_loaded()

        if self._cwes_df is None:
            return SearchResult(pl.DataFrame(schema=cves_df.schema))

        # Normalize CWE ID
        cwe_id = cwe_id.upper()
        if not cwe_id.startswith("CWE-"):
            cwe_id = f"CWE-{cwe_id}"

        matching_cwes = self._cwes_df.filter(pl.col("cwe_id") == cwe_id)
        cve_ids = matching_cwes.get_column("cve_id").unique().to_list()

        result = cves_df.filter(pl.col("cve_id").is_in(cve_ids))
        result = result.sort("date_published", descending=True)
        related = self._get_related_data(cve_ids)

        return SearchResult(result, **related)

    def by_severity(
        self,
        severity: SeverityLevel,
        after: Optional[str] = None,
        before: Optional[str] = None,
    ) -> SearchResult:
        """Search CVEs by severity level.

        Args:
            severity: Severity level (none, low, medium, high, critical).
            after: Only include CVEs published after this date (YYYY-MM-DD).
            before: Only include CVEs published before this date (YYYY-MM-DD).

        Returns:
            SearchResult with matching CVEs.
        """
        cves_df = self._ensure_cves_loaded()

        if self._metrics_df is None:
            return SearchResult(pl.DataFrame(schema=cves_df.schema))

        min_score, max_score = SEVERITY_THRESHOLDS[severity]

        # Get CVE IDs with matching severity based on their BEST metric
        # This ensures consistency with get_best_metric() preference logic
        cvss_metrics = self._metrics_df.filter(
            pl.col("metric_type").str.starts_with("cvss")
            & pl.col("base_score").is_not_null()
        )

        if len(cvss_metrics) == 0:
            return SearchResult(pl.DataFrame(schema=cves_df.schema))

        # Apply preference scoring (same as get_best_metric)
        scored = cvss_metrics.with_columns(
            [
                pl.when(pl.col("source") == "cna")
                .then(100)
                .otherwise(0)
                .alias("source_pref"),
                pl.when(pl.col("metric_type") == "cvssV4_0")
                .then(40)
                .when(pl.col("metric_type") == "cvssV3_1")
                .then(30)
                .when(pl.col("metric_type") == "cvssV3_0")
                .then(20)
                .otherwise(10)
                .alias("version_pref"),
            ]
        ).with_columns(
            [(pl.col("source_pref") + pl.col("version_pref")).alias("preference")]
        )

        # Get best metric per CVE
        best_metrics = (
            scored.sort(["cve_id", "preference"], descending=[False, True])
            .group_by("cve_id")
            .first()
        )

        # Filter to those matching the severity range
        matching = best_metrics.filter(
            (pl.col("base_score") >= min_score) & (pl.col("base_score") <= max_score)
        )

        cve_ids = matching.get_column("cve_id").unique().to_list()

        result = cves_df.filter(pl.col("cve_id").is_in(cve_ids))

        # Apply date filters
        if after:
            result = result.filter(pl.col("date_published") >= after)
        if before:
            result = result.filter(pl.col("date_published") <= before)

        result = result.sort("date_published", descending=True)
        filtered_cve_ids = result.get_column("cve_id").to_list()
        related = self._get_related_data(filtered_cve_ids)

        return SearchResult(result, **related)

    def by_date_range(
        self, after: Optional[str] = None, before: Optional[str] = None
    ) -> SearchResult:
        """Search CVEs by publication date range.

        Args:
            after: Only include CVEs published after this date (YYYY-MM-DD).
            before: Only include CVEs published before this date (YYYY-MM-DD).

        Returns:
            SearchResult with matching CVEs.
        """
        cves_df = self._ensure_cves_loaded()

        result = cves_df

        if after:
            result = result.filter(pl.col("date_published") >= after)
        if before:
            result = result.filter(pl.col("date_published") <= before)

        result = result.sort("date_published", descending=True)
        cve_ids = result.get_column("cve_id").to_list()
        related = self._get_related_data(cve_ids)

        return SearchResult(result, **related)

    def semantic_search(
        self,
        query: str,
        top_k: int = 100,
        min_similarity: float = 0.3,
    ) -> SearchResult:
        """Search CVEs using semantic similarity.

        Uses sentence embeddings to find CVEs with semantically similar
        titles and descriptions to the query.

        Args:
            query: Natural language search query.
            top_k: Maximum number of results to return.
            min_similarity: Minimum cosine similarity threshold (0-1).
                           Default 0.3 filters out weak matches.

        Returns:
            SearchResult with semantically similar CVEs, ordered by similarity.

        Raises:
            FileNotFoundError: If embeddings have not been generated.
            SemanticDependencyError: If semantic dependencies are not installed.
        """
        from cvec.services.embeddings import EmbeddingsService, is_semantic_available

        if not is_semantic_available():
            from cvec.services.embeddings import SemanticDependencyError

            raise SemanticDependencyError("semantic search")

        cves_df = self._ensure_cves_loaded()

        # Perform semantic search
        embeddings_service = EmbeddingsService(config=self.config, quiet=True)
        similarity_results = embeddings_service.search(
            query, top_k=top_k, min_similarity=min_similarity
        )

        if len(similarity_results) == 0:
            return SearchResult(pl.DataFrame(schema=cves_df.schema))

        # Get CVE IDs and their similarity scores
        cve_ids = similarity_results.get_column("cve_id").to_list()
        similarity_scores = dict(
            zip(
                similarity_results.get_column("cve_id").to_list(),
                similarity_results.get_column("similarity_score").to_list(),
            )
        )

        # Get CVE details
        result = cves_df.filter(pl.col("cve_id").is_in(cve_ids))

        # Add similarity score and sort by it
        result = result.with_columns(
            pl.col("cve_id")
            .replace_strict(similarity_scores, default=0.0)
            .alias("similarity_score")
        )
        result = result.sort("similarity_score", descending=True)

        related = self._get_related_data(cve_ids)

        return SearchResult(result, **related)

    def has_embeddings(self) -> bool:
        """Check if semantic search embeddings are available.

        Returns:
            True if embeddings file exists, False otherwise.
        """
        return self.config.cve_embeddings_parquet.exists()

    def recent(self, days: int = 30) -> SearchResult:
        """Get recently published CVEs.

        Args:
            days: Number of days to look back.

        Returns:
            SearchResult with recent CVEs.
        """
        cves_df = self._ensure_cves_loaded()

        cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d")
        result = cves_df.filter(pl.col("date_published") >= cutoff)
        result = result.sort("date_published", descending=True)

        cve_ids = result.get_column("cve_id").to_list()
        related = self._get_related_data(cve_ids)

        return SearchResult(result, **related)

    def stats(self) -> dict:
        """Get overall statistics about the CVE database.

        Returns:
            Dictionary with statistics.
        """
        cves_df = self._ensure_cves_loaded()

        total_cves = len(cves_df)

        # Count by state
        state_counts = cves_df.group_by("state").count().to_dicts()

        # Count by year
        year_counts: dict[str, int] = {}
        for row in cves_df.iter_rows(named=True):
            cve_id = row.get("cve_id", "")
            if cve_id.startswith("CVE-"):
                parts = cve_id.split("-")
                if len(parts) >= 2:
                    year = parts[1]
                    year_counts[year] = year_counts.get(year, 0) + 1

        # Product/vendor stats
        product_count = len(self._products_df) if self._products_df is not None else 0
        unique_products = 0
        unique_vendors = 0
        if self._products_df is not None:
            unique_products = self._products_df.select("product").n_unique()
            unique_vendors = self._products_df.select("vendor").n_unique()

        # Metrics stats
        metrics_count = len(self._metrics_df) if self._metrics_df is not None else 0
        cves_with_cvss = 0
        if self._metrics_df is not None:
            cvss_metrics = self._metrics_df.filter(
                pl.col("metric_type").str.starts_with("cvss")
            )
            cves_with_cvss = cvss_metrics.select("cve_id").n_unique()

        # CWE stats
        cwe_count = len(self._cwes_df) if self._cwes_df is not None else 0
        unique_cwes = 0
        if self._cwes_df is not None:
            unique_cwes = (
                self._cwes_df.filter(pl.col("cwe_id").is_not_null())
                .select("cwe_id")
                .n_unique()
            )

        # Reference stats
        reference_count = (
            len(self._references_df) if self._references_df is not None else 0
        )

        return {
            "total_cves": total_cves,
            "states": {d["state"]: d["count"] for d in state_counts},
            "by_year": dict(sorted(year_counts.items())),
            "total_product_entries": product_count,
            "unique_products": unique_products,
            "unique_vendors": unique_vendors,
            "total_metrics": metrics_count,
            "cves_with_cvss": cves_with_cvss,
            "total_cwe_mappings": cwe_count,
            "unique_cwes": unique_cwes,
            "total_references": reference_count,
        }

    def get_best_metric(self, cve_id: str) -> Optional[dict]:
        """Get the best (most preferred) metric for a CVE.

        Preference order:
        1. CNA metrics over ADP metrics
        2. Newer CVSS versions over older (v4 > v3.1 > v3 > v2)
        3. Falls back to text severity metrics if no CVSS found

        Args:
            cve_id: CVE identifier.

        Returns:
            Dictionary with metric data, or None if no metrics found.
        """
        self._load_data()

        if self._metrics_df is None:
            return None

        # First try CVSS metrics with numeric scores
        cve_metrics = self._metrics_df.filter(
            (pl.col("cve_id") == cve_id)
            & pl.col("metric_type").str.starts_with("cvss")
            & pl.col("base_score").is_not_null()
        )

        if len(cve_metrics) > 0:
            # Score by preference
            scored = cve_metrics.with_columns(
                [
                    pl.when(pl.col("source") == "cna")
                    .then(100)
                    .otherwise(0)
                    .alias("source_pref"),
                    pl.when(pl.col("metric_type") == "cvssV4_0")
                    .then(40)
                    .when(pl.col("metric_type") == "cvssV3_1")
                    .then(30)
                    .when(pl.col("metric_type") == "cvssV3_0")
                    .then(20)
                    .otherwise(10)
                    .alias("version_pref"),
                ]
            ).with_columns(
                [(pl.col("source_pref") + pl.col("version_pref")).alias("preference")]
            )

            best = scored.sort("preference", descending=True).head(1)

            if len(best) > 0:
                return best.to_dicts()[0]

        # Fall back to text severity metrics (type="other")
        text_metrics = self._metrics_df.filter(
            (pl.col("cve_id") == cve_id)
            & (pl.col("metric_type") == "other")
            & pl.col("base_severity").is_not_null()
        )

        if len(text_metrics) > 0:
            # Prefer CNA
            cna_text = text_metrics.filter(pl.col("source") == "cna")
            if len(cna_text) > 0:
                return cna_text.head(1).to_dicts()[0]
            return text_metrics.head(1).to_dicts()[0]

        return None

    def get_description(self, cve_id: str, lang: str = "en") -> Optional[str]:
        """Get the description for a CVE in a specific language.

        Args:
            cve_id: CVE identifier.
            lang: Language code (default: "en").

        Returns:
            Description string, or None if not found.
        """
        self._load_data()

        if self._descriptions_df is None:
            return None

        # Prefer CNA descriptions over ADP
        desc = self._descriptions_df.filter(
            (pl.col("cve_id") == cve_id)
            & (pl.col("lang") == lang)
            & (pl.col("source") == "cna")
        )

        if len(desc) == 0:
            # Fall back to any source
            desc = self._descriptions_df.filter(
                (pl.col("cve_id") == cve_id) & (pl.col("lang") == lang)
            )

        if len(desc) == 0:
            # Fall back to any language
            desc = self._descriptions_df.filter(pl.col("cve_id") == cve_id)

        if len(desc) == 0:
            return None

        result: str = desc.head(1).get_column("value").to_list()[0]
        return result

    def get_kev_info(self, cve_id: str) -> Optional[dict]:
        """Get CISA Known Exploited Vulnerability (KEV) info for a CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            Dictionary with KEV data including dateAdded and reference, or None if not in KEV.
        """
        self._load_data()

        if self._metrics_df is None:
            return None

        kev_metrics = self._metrics_df.filter(
            (pl.col("cve_id") == cve_id) & (pl.col("other_type") == "kev")
        )

        if len(kev_metrics) == 0:
            return None

        kev_row = kev_metrics.head(1).to_dicts()[0]
        other_content = kev_row.get("other_content")

        if other_content:
            import json as json_module

            try:
                result: dict[str, Any] = json_module.loads(other_content)
                return result
            except (json_module.JSONDecodeError, TypeError):
                return {"raw": other_content}
        return None

    def get_ssvc_info(self, cve_id: str) -> Optional[dict[str, Any]]:
        """Get CISA SSVC (Stakeholder-Specific Vulnerability Categorization) info for a CVE.

        Args:
            cve_id: CVE identifier.

        Returns:
            Dictionary with SSVC data, or None if not available.
        """
        self._load_data()

        if self._metrics_df is None:
            return None

        ssvc_metrics = self._metrics_df.filter(
            (pl.col("cve_id") == cve_id) & (pl.col("other_type") == "ssvc")
        )

        if len(ssvc_metrics) == 0:
            return None

        ssvc_row = ssvc_metrics.head(1).to_dicts()[0]
        other_content = ssvc_row.get("other_content")

        if other_content:
            import json as json_module

            try:
                result: dict[str, Any] = json_module.loads(other_content)
                return result
            except (json_module.JSONDecodeError, TypeError):
                return {"raw": other_content}
        return None

    def filter_by_state(self, search_result: SearchResult, state: str) -> SearchResult:
        """Filter an existing SearchResult by CVE state.

        Args:
            search_result: SearchResult to filter.
            state: CVE state to filter by (e.g., "PUBLISHED", "REJECTED").

        Returns:
            New SearchResult with filtered CVEs and related data.
        """
        filtered_cves = search_result.cves.filter(
            pl.col("state").str.to_uppercase() == state.upper()
        )

        cve_ids = filtered_cves.get_column("cve_id").to_list()
        related = self._get_related_data(cve_ids)

        return SearchResult(filtered_cves, **related)

    def filter_by_kev(self, result: SearchResult) -> SearchResult:
        """Filter an existing SearchResult to only include CVEs in CISA KEV.

        Args:
            result: SearchResult to filter.

        Returns:
            New SearchResult with only KEV CVEs.
        """
        self._load_data()

        if self._metrics_df is None:
            return SearchResult(pl.DataFrame(schema=result.cves.schema))

        # Get CVE IDs that have KEV entries
        kev_cves = (
            self._metrics_df.filter(pl.col("other_type") == "kev")
            .get_column("cve_id")
            .unique()
            .to_list()
        )

        cve_ids_in_result = set(result.cves.get_column("cve_id").to_list())
        kev_cve_ids = [cve_id for cve_id in kev_cves if cve_id in cve_ids_in_result]

        filtered_cves = result.cves.filter(pl.col("cve_id").is_in(kev_cve_ids))
        related = self._get_related_data(kev_cve_ids)

        return SearchResult(filtered_cves, **related)

    @staticmethod
    def validate_date(date_str: str) -> bool:
        """Validate a date string is in YYYY-MM-DD format.

        Args:
            date_str: Date string to validate.

        Returns:
            True if valid, False otherwise.
        """
        try:
            datetime.strptime(date_str, "%Y-%m-%d")
            return True
        except ValueError:
            return False

    def filter_by_date(
        self,
        result: SearchResult,
        after: Optional[str] = None,
        before: Optional[str] = None,
    ) -> SearchResult:
        """Filter an existing SearchResult by date range.

        Args:
            result: SearchResult to filter.
            after: Only include CVEs published after this date (YYYY-MM-DD).
            before: Only include CVEs published before this date (YYYY-MM-DD).

        Returns:
            New SearchResult with filtered CVEs and related data.

        Raises:
            ValueError: If date format is invalid.
        """
        if after and not self.validate_date(after):
            raise ValueError(f"Invalid date format: {after}. Expected YYYY-MM-DD.")
        if before and not self.validate_date(before):
            raise ValueError(f"Invalid date format: {before}. Expected YYYY-MM-DD.")

        filtered_cves = result.cves

        if after:
            filtered_cves = filtered_cves.filter(pl.col("date_published") >= after)
        if before:
            filtered_cves = filtered_cves.filter(pl.col("date_published") <= before)

        # Get related data for filtered CVEs
        cve_ids = filtered_cves.get_column("cve_id").to_list()
        related = self._get_related_data(cve_ids)

        return SearchResult(filtered_cves, **related)

    def filter_by_severity(
        self, result: SearchResult, severity: SeverityLevel
    ) -> SearchResult:
        """Filter an existing SearchResult by severity level.

        Args:
            result: SearchResult to filter.
            severity: Severity level (none, low, medium, high, critical).

        Returns:
            New SearchResult with CVEs matching severity level.
        """
        if result.metrics is None or len(result.metrics) == 0:
            return SearchResult(pl.DataFrame(schema=result.cves.schema))

        min_score, max_score = SEVERITY_THRESHOLDS[severity]

        # Get CVE IDs with matching severity based on their BEST metric
        # This ensures consistency with get_best_metric() preference logic
        cve_ids_in_result = set(result.cves.get_column("cve_id").to_list())

        cvss_metrics = result.metrics.filter(
            pl.col("cve_id").is_in(cve_ids_in_result)
            & pl.col("metric_type").str.starts_with("cvss")
            & pl.col("base_score").is_not_null()
        )

        if len(cvss_metrics) == 0:
            return SearchResult(pl.DataFrame(schema=result.cves.schema))

        # Apply preference scoring (same as get_best_metric)
        scored = cvss_metrics.with_columns(
            [
                pl.when(pl.col("source") == "cna")
                .then(100)
                .otherwise(0)
                .alias("source_pref"),
                pl.when(pl.col("metric_type") == "cvssV4_0")
                .then(40)
                .when(pl.col("metric_type") == "cvssV3_1")
                .then(30)
                .when(pl.col("metric_type") == "cvssV3_0")
                .then(20)
                .otherwise(10)
                .alias("version_pref"),
            ]
        ).with_columns(
            [(pl.col("source_pref") + pl.col("version_pref")).alias("preference")]
        )

        # Get best metric per CVE
        best_metrics = (
            scored.sort(["cve_id", "preference"], descending=[False, True])
            .group_by("cve_id")
            .first()
        )

        # Filter to those matching the severity range
        matching = best_metrics.filter(
            (pl.col("base_score") >= min_score) & (pl.col("base_score") <= max_score)
        )

        cve_ids = matching.get_column("cve_id").unique().to_list()

        filtered_cves = result.cves.filter(pl.col("cve_id").is_in(cve_ids))
        related = self._get_related_data(cve_ids)

        return SearchResult(filtered_cves, **related)
