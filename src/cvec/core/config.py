"""Core configuration for cvec."""

import os
from datetime import datetime
from pathlib import Path
from typing import Optional

# Default paths relative to project root
DEFAULT_DATA_DIR = Path("data")
DEFAULT_DOWNLOAD_DIR = Path("download")
DEFAULT_CVE_SUBDIR = "cve_github/individual"

# Default settings
DEFAULT_YEARS = 10
CURRENT_YEAR = datetime.now().year


class Config:
    """Configuration management for cvec.

    Reads from environment variables or uses defaults.
    """

    def __init__(
        self,
        data_dir: Optional[Path] = None,
        download_dir: Optional[Path] = None,
        default_years: Optional[int] = None,
    ):
        # Resolve project root (assuming config.py is in src/cvec/core/)
        self._project_root = Path(__file__).parent.parent.parent.parent

        # Data directory
        self.data_dir = data_dir or Path(
            os.environ.get("CVE_DATA_DIR", self._project_root / DEFAULT_DATA_DIR)
        )

        # Download directory
        self.download_dir = download_dir or Path(
            os.environ.get(
                "CVE_DOWNLOAD_DIR", self._project_root / DEFAULT_DOWNLOAD_DIR
            )
        )

        # Default years to download
        self.default_years = default_years or int(
            os.environ.get("CVE_DEFAULT_YEARS", DEFAULT_YEARS)
        )

    @property
    def cve_dir(self) -> Path:
        """Directory containing individual CVE JSON files."""
        return self.data_dir / DEFAULT_CVE_SUBDIR

    @property
    def cves_parquet(self) -> Path:
        """Path to extracted CVEs parquet file."""
        return self.data_dir / "cves.parquet"

    @property
    def cve_descriptions_parquet(self) -> Path:
        """Path to CVE descriptions parquet file."""
        return self.data_dir / "cve_descriptions.parquet"

    @property
    def cve_metrics_parquet(self) -> Path:
        """Path to CVE metrics parquet file."""
        return self.data_dir / "cve_metrics.parquet"

    @property
    def cve_products_parquet(self) -> Path:
        """Path to CVE products parquet file."""
        return self.data_dir / "cve_products.parquet"

    @property
    def cve_versions_parquet(self) -> Path:
        """Path to CVE versions parquet file."""
        return self.data_dir / "cve_versions.parquet"

    @property
    def cve_cwes_parquet(self) -> Path:
        """Path to CVE-CWE mapping parquet file."""
        return self.data_dir / "cve_cwes.parquet"

    @property
    def cve_references_parquet(self) -> Path:
        """Path to CVE references parquet file."""
        return self.data_dir / "cve_references.parquet"

    @property
    def cve_credits_parquet(self) -> Path:
        """Path to CVE credits parquet file."""
        return self.data_dir / "cve_credits.parquet"

    @property
    def cve_tags_parquet(self) -> Path:
        """Path to CVE tags parquet file."""
        return self.data_dir / "cve_tags.parquet"

    @property
    def cve_embeddings_parquet(self) -> Path:
        """Path to CVE embeddings parquet file for semantic search."""
        return self.data_dir / "cve_embeddings.parquet"

    # Legacy alias for backward compatibility
    @property
    def cve_cwe_parquet(self) -> Path:
        """Path to CVE-CWE mapping parquet file (legacy alias)."""
        return self.cve_cwes_parquet

    @property
    def capec_json(self) -> Path:
        """Path to CAPEC JSON file."""
        return self.data_dir / "capec.json"

    @property
    def cwe_json(self) -> Path:
        """Path to CWE JSON file."""
        return self.data_dir / "cwe.json"

    @property
    def capec_xml(self) -> Path:
        """Path to downloaded CAPEC XML file."""
        return self.download_dir / "capec" / "attack_patterns.xml"

    @property
    def cwe_xml(self) -> Path:
        """Path to downloaded CWE XML file."""
        return self.download_dir / "cwe" / "cwec_latest.xml"

    @property
    def cve_zip(self) -> Path:
        """Path to downloaded CVE zip file."""
        return self.download_dir / "cve_github" / "cvelistV5-main.zip"

    def get_year_range(self, years: Optional[int] = None) -> tuple[int, int]:
        """Get the year range to process.

        Args:
            years: Number of years to include. If None, uses default_years.

        Returns:
            Tuple of (start_year, end_year) inclusive.
        """
        years = years or self.default_years
        end_year = CURRENT_YEAR
        start_year = end_year - years + 1
        return (start_year, end_year)

    def ensure_directories(self) -> None:
        """Create necessary directories if they don't exist."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.download_dir.mkdir(parents=True, exist_ok=True)
        (self.download_dir / "capec").mkdir(parents=True, exist_ok=True)
        (self.download_dir / "cwe").mkdir(parents=True, exist_ok=True)
        (self.download_dir / "cve_github").mkdir(parents=True, exist_ok=True)


# Global default config instance
_default_config: Optional[Config] = None


def get_config() -> Config:
    """Get the default configuration instance."""
    global _default_config
    if _default_config is None:
        _default_config = Config()
    return _default_config
