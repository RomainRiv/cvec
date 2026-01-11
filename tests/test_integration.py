"""Integration tests for the CVE analyzer."""

import polars as pl
import pytest

from cvec.core.config import Config
from cvec.models.cve_model import CveJsonRecordFormat
from cvec.services.extractor import (
    ExtractorService,
    _extract_single_cve,
)
from cvec.services.search import CVESearchService


class TestExtractionToSearchPipeline:
    """Integration tests for the extract -> search pipeline."""

    def test_extract_and_search_single_cve(self, sample_cve_files):
        """Test extracting a CVE and then searching for it."""
        # Extract
        extractor = ExtractorService(config=sample_cve_files)
        result = extractor.extract_all(years=[2022])

        # Check result has paths
        assert "paths" in result
        assert result["paths"]["cves"].exists()

        # Search
        search = CVESearchService(config=sample_cve_files)
        search_result = search.by_id("CVE-2022-2196")

        assert search_result.count == 1
        cve = search_result.to_dicts()[0]
        assert cve["cve_id"] == "CVE-2022-2196"

        # Check metric via service
        metric = search.get_best_metric("CVE-2022-2196")
        assert metric is not None
        assert metric["base_score"] == 5.8

    def test_extract_and_search_by_product(self, sample_cve_files):
        """Test extracting CVEs and searching by product."""
        # Extract all sample years
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2016, 2022, 2023, 2024])

        # Search by product
        search = CVESearchService(config=sample_cve_files)
        result = search.by_product("OpenSSL")

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2016-7054" in cve_ids

    def test_extract_and_search_by_cwe(self, sample_cve_files):
        """Test extracting CVEs and searching by CWE."""
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2022])

        search = CVESearchService(config=sample_cve_files)
        result = search.by_cwe("CWE-1188")

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_extract_preserves_severity_text(self, sample_cve_files):
        """Test that text severity is preserved through extraction."""
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2016])

        search = CVESearchService(config=sample_cve_files)
        result = search.by_id("CVE-2016-7054")

        assert result.count == 1
        # Check metric - should be an "other" type with text severity
        metric = search.get_best_metric("CVE-2016-7054")
        assert metric is not None
        assert metric["base_severity"] == "High"

    def test_extract_adp_metrics(self, sample_cve_files):
        """Test that ADP metrics are extracted."""
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2024])

        search = CVESearchService(config=sample_cve_files)
        result = search.by_id("CVE-2024-1234")

        assert result.count == 1
        metric = search.get_best_metric("CVE-2024-1234")
        assert metric is not None
        assert metric["base_score"] == 9.8
        assert metric["source"].startswith("adp:")


class TestCVEDataIntegrity:
    """Tests for data integrity through the pipeline."""

    def test_all_fields_extracted(self, sample_cve_files):
        """Test that all expected fields are extracted."""
        from tests.conftest import SAMPLE_CVE_2022_2196

        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_2022_2196)
        result = _extract_single_cve(cve_model)

        cve = result.cve
        assert cve.cve_id == "CVE-2022-2196"
        assert cve.state == "PUBLISHED"
        assert cve.assigner_short_name == "Google"
        assert cve.cna_title is not None
        assert cve.date_published is not None

        # Check descriptions are extracted
        assert len(result.descriptions) >= 1
        en_desc = [d for d in result.descriptions if d.lang == "en"]
        assert len(en_desc) >= 1

        # Check metrics are extracted
        cvss_metrics = [m for m in result.metrics if m.metric_type == "cvssV3_1"]
        assert len(cvss_metrics) >= 1
        assert cvss_metrics[0].base_score == 5.8
        assert cvss_metrics[0].vector_string is not None

    def test_products_have_required_fields(self, sample_cve_files):
        """Test that products have required fields."""
        from tests.conftest import SAMPLE_CVE_2022_2196

        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_2022_2196)
        result = _extract_single_cve(cve_model)

        assert len(result.products) >= 1
        product = result.products[0]
        assert product.cve_id == "CVE-2022-2196"
        assert product.vendor == "Linux"
        assert product.product == "Linux Kernel"

    def test_cwes_have_required_fields(self, sample_cve_files):
        """Test that CWE mappings have required fields."""
        from tests.conftest import SAMPLE_CVE_2022_2196

        cve_model = CveJsonRecordFormat.model_validate(SAMPLE_CVE_2022_2196)
        result = _extract_single_cve(cve_model)

        assert len(result.cwes) >= 1
        cwe = result.cwes[0]
        assert cwe.cve_id == "CVE-2022-2196"
        assert cwe.cwe_id == "CWE-1188"


class TestParquetOutput:
    """Tests for Parquet file output."""

    def test_parquet_files_created(self, sample_cve_files):
        """Test that extraction creates Parquet files."""
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2022])

        assert sample_cve_files.cves_parquet.exists()
        assert sample_cve_files.cve_products_parquet.exists()
        assert sample_cve_files.cve_cwe_parquet.exists()

    def test_parquet_readable(self, sample_cve_files):
        """Test that Parquet files are readable."""
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2022])

        cves_df = pl.read_parquet(sample_cve_files.cves_parquet)
        assert len(cves_df) >= 1
        assert "cve_id" in cves_df.columns
        assert "state" in cves_df.columns

    def test_parquet_schema(self, sample_cve_files):
        """Test that Parquet files have expected schema."""
        extractor = ExtractorService(config=sample_cve_files)
        extractor.extract_all(years=[2022])

        cves_df = pl.read_parquet(sample_cve_files.cves_parquet)

        expected_columns = [
            "cve_id",
            "state",
            "assigner_short_name",
            "cna_title",
            "date_published",
        ]
        for col in expected_columns:
            assert col in cves_df.columns, f"Missing column: {col}"

        # Check metrics table
        metrics_df = pl.read_parquet(sample_cve_files.cve_metrics_parquet)
        metrics_cols = [
            "cve_id",
            "metric_type",
            "source",
            "base_score",
            "base_severity",
        ]
        for col in metrics_cols:
            assert col in metrics_df.columns, f"Missing metrics column: {col}"


class TestSearchWithRealData:
    """Tests using real CVE data from the repository (if available)."""

    @pytest.fixture
    def real_config(self):
        """Get config pointing to real data directory."""
        config = Config()
        if not config.cves_parquet.exists():
            pytest.skip("Real CVE data not available - run 'cvec db update' first")
        # Check if the parquet has the new schema by looking for cve_id column
        import polars as pl

        try:
            df = pl.read_parquet(config.cves_parquet)
            if "cve_id" not in df.columns:
                pytest.skip(
                    "Real CVE data is in old schema format - "
                    "run 'cvec db build extract-parquet' to regenerate"
                )
        except Exception:
            pytest.skip("Error reading parquet file")
        return config

    def test_search_known_cve(self, real_config):
        """Test searching for a known CVE in real data."""
        search = CVESearchService(config=real_config)
        result = search.by_id("CVE-2024-6387")  # regreSSHion

        if result.count == 0:
            pytest.skip("CVE-2024-6387 not in extracted data")

        cve = result.to_dicts()[0]
        assert cve["cve_id"] == "CVE-2024-6387"
        assert cve["state"] == "PUBLISHED"

    def test_search_openssl_cves(self, real_config):
        """Test searching for OpenSSL CVEs in real data."""
        search = CVESearchService(config=real_config)
        result = search.by_product("openssl", fuzzy=True)

        # There should be many OpenSSL CVEs
        assert result.count > 0

    def test_search_critical_severity(self, real_config):
        """Test searching for critical CVEs in real data."""
        search = CVESearchService(config=real_config)
        result = search.by_severity("critical")

        # There should be many critical CVEs
        assert result.count > 0

        # All should have high CVSS - check via get_best_metric
        for cve in result.to_dicts()[:10]:  # Check first 10
            metric = search.get_best_metric(cve["cve_id"])
            if metric is not None and metric.get("base_score") is not None:
                score = metric["base_score"]
                assert (
                    score >= 9.0
                ), f"CVE {cve['cve_id']} has score {score}, expected >= 9.0"
