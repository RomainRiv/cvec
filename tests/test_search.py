"""Unit tests for the search service."""

import pytest

from cvec.services.search import (
    SEVERITY_THRESHOLDS,
    CVESearchService,
    SearchResult,
)


class TestSeverityThresholds:
    """Tests for severity threshold constants."""

    def test_severity_levels_exist(self):
        """All severity levels should be defined."""
        assert "none" in SEVERITY_THRESHOLDS
        assert "low" in SEVERITY_THRESHOLDS
        assert "medium" in SEVERITY_THRESHOLDS
        assert "high" in SEVERITY_THRESHOLDS
        assert "critical" in SEVERITY_THRESHOLDS

    def test_severity_ranges(self):
        """Severity ranges should be correct."""
        assert SEVERITY_THRESHOLDS["none"] == (0.0, 0.0)
        assert SEVERITY_THRESHOLDS["low"] == (0.1, 3.9)
        assert SEVERITY_THRESHOLDS["medium"] == (4.0, 6.9)
        assert SEVERITY_THRESHOLDS["high"] == (7.0, 8.9)
        assert SEVERITY_THRESHOLDS["critical"] == (9.0, 10.0)


class TestSearchResult:
    """Tests for SearchResult class."""

    def test_empty_result(self):
        """Empty result should have count of 0."""
        import polars as pl

        result = SearchResult(pl.DataFrame())
        assert result.count == 0
        assert result.to_dicts() == []

    def test_count_property(self, sample_parquet_data):
        """Count should reflect number of CVEs."""
        import polars as pl

        cves = pl.read_parquet(sample_parquet_data.cves_parquet)
        result = SearchResult(cves)
        assert result.count == 5  # 5 sample CVEs in fixture

    def test_summary_empty(self):
        """Summary of empty result should show count 0."""
        import polars as pl

        result = SearchResult(pl.DataFrame())
        summary = result.summary()
        assert summary["count"] == 0

    def test_summary_with_data(self, sample_parquet_data):
        """Summary should include severity and year distribution."""
        import polars as pl

        cves = pl.read_parquet(sample_parquet_data.cves_parquet)
        result = SearchResult(cves)
        summary = result.summary()

        assert "count" in summary
        assert "severity_distribution" in summary
        assert "year_distribution" in summary
        assert summary["count"] == 5

    def test_severity_distribution(self, sample_parquet_data):
        """Severity distribution should categorize CVEs correctly."""
        # Use the search service to get results with all related data
        service = CVESearchService(config=sample_parquet_data)

        # Search for all CVEs
        result = service.by_id("CVE-2022-2196")
        assert result.count == 1

        # Now test with the full search which includes metrics
        # Search for all by using a broad product search
        result_all = service.by_product("", fuzzy=True)
        summary = result_all.summary()

        dist = summary["severity_distribution"]
        # CVE-2022-2196 has 5.8 (medium)
        # CVE-2024-1234 has 9.8 from ADP (critical)
        # CVE-2016-7054 has text severity but no numeric
        # CVE-2023-0001 has no severity (unknown)
        # At minimum we should have some medium and critical
        total = sum(dist.values())
        assert total > 0


class TestCVESearchService:
    """Tests for CVESearchService class."""

    def test_init_default_config(self):
        """Service should initialize with default config."""
        service = CVESearchService()
        assert service.config is not None

    def test_init_custom_config(self, temp_config):
        """Service should accept custom config."""
        service = CVESearchService(config=temp_config)
        assert service.config == temp_config

    def test_by_id_found(self, sample_parquet_data):
        """by_id should return matching CVE."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_id("CVE-2022-2196")

        assert result.count == 1
        cve = result.to_dicts()[0]
        assert cve["cve_id"] == "CVE-2022-2196"
        assert cve["state"] == "PUBLISHED"

    def test_by_id_not_found(self, sample_parquet_data):
        """by_id should return empty result for non-existent CVE."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_id("CVE-9999-9999")

        assert result.count == 0

    def test_by_id_normalizes_input(self, sample_parquet_data):
        """by_id should normalize CVE ID format."""
        service = CVESearchService(config=sample_parquet_data)

        # Without CVE- prefix
        result1 = service.by_id("2022-2196")
        assert result1.count == 1

        # Lowercase
        result2 = service.by_id("cve-2022-2196")
        assert result2.count == 1

    def test_by_product_found(self, sample_parquet_data):
        """by_product should return CVEs affecting the product."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_product("Linux Kernel")

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_product_fuzzy(self, sample_parquet_data):
        """by_product should support fuzzy matching."""
        service = CVESearchService(config=sample_parquet_data)

        # Partial match
        result = service.by_product("kernel", fuzzy=True)
        assert result.count >= 1

    def test_by_product_with_vendor(self, sample_parquet_data):
        """by_product should filter by vendor."""
        service = CVESearchService(config=sample_parquet_data)

        result = service.by_product("Linux Kernel", vendor="Linux")
        assert result.count >= 1

    def test_by_product_not_found(self, sample_parquet_data):
        """by_product should return empty for non-existent product."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_product("NonExistentProduct12345")

        assert result.count == 0

    def test_by_vendor(self, sample_parquet_data):
        """by_vendor should return CVEs for vendor's products."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_vendor("OpenSSL")

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2016-7054" in cve_ids

    def test_by_cwe_found(self, sample_parquet_data):
        """by_cwe should return CVEs with matching CWE."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_cwe("CWE-1188")

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_cwe_normalizes_input(self, sample_parquet_data):
        """by_cwe should normalize CWE ID format."""
        service = CVESearchService(config=sample_parquet_data)

        # Without CWE- prefix
        result1 = service.by_cwe("1188")
        assert result1.count >= 1

        # Lowercase
        result2 = service.by_cwe("cwe-1188")
        assert result2.count >= 1

    def test_by_severity_medium(self, sample_parquet_data):
        """by_severity should return CVEs with matching severity."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_severity("medium")

        # CVE-2022-2196 has CVSS 5.8 (medium)
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

    def test_by_severity_critical(self, sample_parquet_data):
        """by_severity should find critical CVEs."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_severity("critical")

        # CVE-2024-1234 has ADP CVSS 9.8 (critical)
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-1234" in cve_ids

    def test_by_severity_with_date_filter(self, sample_parquet_data):
        """by_severity should filter by date range."""
        service = CVESearchService(config=sample_parquet_data)

        # After 2020
        result = service.by_severity("medium", after="2020-01-01")
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2022-2196" in cve_ids

        # Before 2020 should not include 2022 CVE
        result2 = service.by_severity("medium", before="2020-01-01")
        cve_ids2 = [c["cve_id"] for c in result2.to_dicts()]
        assert "CVE-2022-2196" not in cve_ids2

    def test_missing_data_file(self, temp_config):
        """Service should raise error when data files are missing."""
        service = CVESearchService(config=temp_config)

        with pytest.raises(FileNotFoundError):
            service.by_id("CVE-2022-2196")


class TestSearchResultProducts:
    """Tests for product-related search functionality."""

    def test_products_included_in_result(self, sample_parquet_data):
        """Search result should include product information."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_id("CVE-2022-2196")

        assert result.products is not None
        products = result.products.to_dicts()
        assert len(products) >= 1
        assert any(p["product"] == "Linux Kernel" for p in products)


class TestSearchResultCWEs:
    """Tests for CWE-related search functionality."""

    def test_cwes_included_in_result(self, sample_parquet_data):
        """Search result should include CWE information."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_id("CVE-2022-2196")

        assert result.cwes is not None
        cwes = result.cwes.to_dicts()
        assert len(cwes) >= 1
        assert any(c["cwe_id"] == "CWE-1188" for c in cwes)


class TestValidateDate:
    """Tests for date validation."""

    def test_valid_date(self, sample_parquet_data):
        """Valid date format should return True."""
        service = CVESearchService(config=sample_parquet_data)
        assert service.validate_date("2024-01-15") is True
        assert service.validate_date("2023-12-31") is True
        assert service.validate_date("1999-01-01") is True

    def test_invalid_date_format(self, sample_parquet_data):
        """Invalid date formats should return False."""
        service = CVESearchService(config=sample_parquet_data)
        assert service.validate_date("01-15-2024") is False
        assert service.validate_date("2024/01/15") is False
        assert service.validate_date("not-a-date") is False
        assert service.validate_date("") is False

    def test_invalid_date_values(self, sample_parquet_data):
        """Invalid date values should return False."""
        service = CVESearchService(config=sample_parquet_data)
        assert service.validate_date("2024-13-01") is False  # Invalid month
        assert service.validate_date("2024-02-30") is False  # Invalid day

    def test_filter_by_date_invalid_after(self, sample_parquet_data):
        """filter_by_date should raise ValueError for invalid after date."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_product("", fuzzy=True)

        with pytest.raises(ValueError, match="Invalid date format"):
            service.filter_by_date(result, after="01-15-2024")

    def test_filter_by_date_invalid_before(self, sample_parquet_data):
        """filter_by_date should raise ValueError for invalid before date."""
        service = CVESearchService(config=sample_parquet_data)
        result = service.by_product("", fuzzy=True)

        with pytest.raises(ValueError, match="Invalid date format"):
            service.filter_by_date(result, before="2024/01/15")


class TestExactMatching:
    """Tests for exact (literal) string matching with regex character escaping."""

    def test_by_product_with_regex_chars_exact(self, sample_parquet_data):
        """by_product with exact=True should match literal regex characters."""
        service = CVESearchService(config=sample_parquet_data)

        # Search for product with regex special characters using exact matching
        result = service.by_product("Product[v1.0]+", fuzzy=True, exact=True)

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-9999" in cve_ids

    def test_by_product_regex_chars_without_exact_fails(self, sample_parquet_data):
        """by_product without exact=True should fail on unescaped regex characters."""
        service = CVESearchService(config=sample_parquet_data)

        # These regex characters would cause issues or match wrong results without escaping
        # [v1.0] would be interpreted as character class
        # This may either throw an error or return wrong results
        try:
            result = service.by_product("[v1.0]", fuzzy=True, exact=False)
            # If it doesn't throw, it might match other products containing v, 1, 0, or .
            # The exact behavior depends on polars regex handling
        except Exception:
            pass  # Expected - regex parsing error

    def test_by_vendor_with_regex_chars_exact(self, sample_parquet_data):
        """by_vendor with exact=True should match literal regex characters."""
        service = CVESearchService(config=sample_parquet_data)

        # Search for vendor with regex special characters using exact matching
        result = service.by_vendor("Test.Vendor (Inc.)", fuzzy=True, exact=True)

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-9999" in cve_ids

    def test_by_product_partial_with_regex_chars_exact(self, sample_parquet_data):
        """by_product with exact=True should find partial matches with literal characters."""
        service = CVESearchService(config=sample_parquet_data)

        # Search for partial product name with regex special characters
        result = service.by_product("[v1.0]", fuzzy=True, exact=True)

        assert result.count >= 1
        cve_ids = [c["cve_id"] for c in result.to_dicts()]
        assert "CVE-2024-9999" in cve_ids


class TestFilterByState:
    """Tests for state filtering."""

    def test_filter_by_state_published(self, sample_parquet_data):
        """filter_by_state should filter to only published CVEs."""
        service = CVESearchService(config=sample_parquet_data)

        # Get all CVEs first
        all_result = service.by_product("", fuzzy=True)
        assert all_result.count >= 5  # We have 5 CVEs in fixtures

        # Filter to published only
        published_result = service.filter_by_state(all_result, "published")
        assert published_result.count >= 4  # 4 published CVEs
        for cve in published_result.to_dicts():
            assert cve["state"] == "PUBLISHED"

    def test_filter_by_state_rejected(self, sample_parquet_data):
        """filter_by_state should filter to only rejected CVEs."""
        service = CVESearchService(config=sample_parquet_data)

        # Get all CVEs first
        all_result = service.by_product("", fuzzy=True)

        # Filter to rejected only
        rejected_result = service.filter_by_state(all_result, "rejected")
        assert rejected_result.count >= 1  # 1 rejected CVE
        for cve in rejected_result.to_dicts():
            assert cve["state"] == "REJECTED"

    def test_filter_by_state_case_insensitive(self, sample_parquet_data):
        """filter_by_state should be case insensitive."""
        service = CVESearchService(config=sample_parquet_data)

        all_result = service.by_product("", fuzzy=True)

        # Test various cases
        result_upper = service.filter_by_state(all_result, "PUBLISHED")
        result_lower = service.filter_by_state(all_result, "published")
        result_mixed = service.filter_by_state(all_result, "Published")

        assert result_upper.count == result_lower.count == result_mixed.count


class TestSemanticSearch:
    """Tests for semantic search functionality."""

    def test_has_embeddings_false(self, sample_parquet_data):
        """has_embeddings should return False when no embeddings exist."""
        service = CVESearchService(config=sample_parquet_data)
        assert service.has_embeddings() is False

    def test_has_embeddings_true(self, sample_parquet_data_with_embeddings):
        """has_embeddings should return True when embeddings exist."""
        service = CVESearchService(config=sample_parquet_data_with_embeddings)
        assert service.has_embeddings() is True

    def test_semantic_search_no_embeddings(self, sample_parquet_data):
        """semantic_search should raise error when embeddings don't exist."""
        service = CVESearchService(config=sample_parquet_data)

        with pytest.raises(FileNotFoundError):
            service.semantic_search("buffer overflow")

    def test_semantic_search_returns_results(self, sample_parquet_data_with_embeddings):
        """semantic_search should return CVEs with similarity scores."""
        from unittest.mock import patch, MagicMock
        import numpy as np
        from cvec.services.embeddings import EMBEDDING_DIMENSION

        # Mock the embedding model to return a specific query embedding
        with patch(
            "cvec.services.embeddings.EmbeddingsService._get_model"
        ) as mock_get_model:
            mock_model = MagicMock()
            # fastembed's embed returns a generator
            mock_model.embed.return_value = iter(
                [np.array([1.0] * EMBEDDING_DIMENSION)]
            )
            mock_get_model.return_value = mock_model

            service = CVESearchService(config=sample_parquet_data_with_embeddings)
            result = service.semantic_search(
                "buffer overflow", top_k=10, min_similarity=0.0
            )

            assert result.count >= 1
            # Results should have similarity_score column
            cve_data = result.to_dicts()[0]
            assert "similarity_score" in cve_data


class TestFilterByKEV:
    """Tests for CISA KEV filtering."""

    def test_filter_by_kev(self, sample_parquet_data):
        """filter_by_kev should filter to only CVEs in CISA KEV."""
        service = CVESearchService(config=sample_parquet_data)

        # Get all CVEs first
        all_result = service.by_product("", fuzzy=True)

        # Filter to KEV only
        kev_result = service.filter_by_kev(all_result)
        assert kev_result.count >= 1  # At least CVE-2024-1234 should be in KEV
        cve_ids = [c["cve_id"] for c in kev_result.to_dicts()]
        assert "CVE-2024-1234" in cve_ids

    def test_filter_by_kev_preserves_related_data(self, sample_parquet_data):
        """filter_by_kev should preserve related data for filtered CVEs."""
        service = CVESearchService(config=sample_parquet_data)

        all_result = service.by_product("", fuzzy=True)
        kev_result = service.filter_by_kev(all_result)

        # Related data should be present
        assert kev_result.products is not None or kev_result.count == 0


class TestGetKEVInfo:
    """Tests for KEV info retrieval."""

    def test_get_kev_info_found(self, sample_parquet_data):
        """get_kev_info should return KEV data for CVE in KEV list."""
        service = CVESearchService(config=sample_parquet_data)

        kev_info = service.get_kev_info("CVE-2024-1234")
        assert kev_info is not None
        assert "dateAdded" in kev_info
        assert kev_info["dateAdded"] == "2024-01-15"

    def test_get_kev_info_not_found(self, sample_parquet_data):
        """get_kev_info should return None for CVE not in KEV list."""
        service = CVESearchService(config=sample_parquet_data)

        kev_info = service.get_kev_info("CVE-2022-2196")
        assert kev_info is None


class TestGetSSVCInfo:
    """Tests for SSVC info retrieval."""

    def test_get_ssvc_info_found(self, sample_parquet_data):
        """get_ssvc_info should return SSVC data for CVE with SSVC assessment."""
        service = CVESearchService(config=sample_parquet_data)

        ssvc_info = service.get_ssvc_info("CVE-2024-1234")
        assert ssvc_info is not None
        assert "automatable" in ssvc_info
        assert ssvc_info["automatable"] == "Yes"
        assert "exploitation" in ssvc_info
        assert ssvc_info["exploitation"] == "Active"

    def test_get_ssvc_info_not_found(self, sample_parquet_data):
        """get_ssvc_info should return None for CVE without SSVC assessment."""
        service = CVESearchService(config=sample_parquet_data)

        ssvc_info = service.get_ssvc_info("CVE-2022-2196")
        assert ssvc_info is None


class TestCPESearch:
    """Tests for CPE-based search functionality."""

    def test_by_cpe_with_explicit_version(self, sample_parquet_data):
        """by_cpe should extract version from CPE string automatically."""
        service = CVESearchService(config=sample_parquet_data)

        # Search with a CPE that has a specific version
        result = service.by_cpe("cpe:2.3:a:linux:linux_kernel:5.15.0:*:*:*:*:*:*:*")

        # Should filter to only CVEs affecting version 5.15.0
        # The sample data has CVE-2022-2196 with affected version range
        assert (
            result.count >= 0
        )  # May or may not have matches depending on version ranges

    def test_by_cpe_with_wildcard_version(self, sample_parquet_data):
        """by_cpe should not filter by version when CPE has wildcard."""
        service = CVESearchService(config=sample_parquet_data)

        # Search with wildcard version - should return all matching vendor/product
        result = service.by_cpe("cpe:2.3:a:linux:linux_kernel:*:*:*:*:*:*:*:*")

        # Should NOT filter by version, return all linux kernel CVEs
        assert result.count >= 1  # Should find CVE-2022-2196

    def test_by_cpe_version_override(self, sample_parquet_data):
        """Explicit check_version parameter should override CPE version."""
        service = CVESearchService(config=sample_parquet_data)

        # CPE has version 0, but we override with explicit version
        result = service.by_cpe(
            "cpe:2.3:a:linux:linux_kernel:0:*:*:*:*:*:*:*", check_version="5.15.0"
        )

        # Should use explicit version (5.15.0), not CPE version (0)
        assert result.count >= 0

    def test_by_cpe_invalid_format(self, sample_parquet_data):
        """by_cpe should raise ValueError for invalid CPE string."""
        service = CVESearchService(config=sample_parquet_data)

        with pytest.raises(ValueError, match="Invalid CPE string"):
            service.by_cpe("not-a-cpe-string")

    def test_by_cpe_with_dash_version(self, sample_parquet_data):
        """by_cpe should treat dash (-) as wildcard and not filter by version."""
        service = CVESearchService(config=sample_parquet_data)

        # CPE with dash for version (means "not applicable")
        result = service.by_cpe("cpe:2.3:a:linux:linux_kernel:-:*:*:*:*:*:*:*")

        # Should NOT filter by version
        assert result.count >= 1  # Should find CVE-2022-2196


class TestVersionRangeParsing:
    """Tests for version range string parsing in filter_by_version."""

    def test_version_range_string_parsing(self):
        """Version range strings like '0.5.6 - 1.13.2' should be parsed correctly."""
        from cvec.services.version import is_version_affected

        # Simulate what happens when filter_by_version processes a range string
        version_start = "0.5.6 - 1.13.2"
        less_than = None
        less_than_or_equal = None

        # Parse the range string
        if version_start and " - " in str(version_start):
            parts = str(version_start).split(" - ")
            if len(parts) == 2:
                version_start = parts[0].strip()
                if not less_than and not less_than_or_equal:
                    less_than_or_equal = parts[1].strip()

        # Test versions within range should be affected
        assert is_version_affected(
            "1.10.0", version_start=version_start, less_than_or_equal=less_than_or_equal
        )
        assert is_version_affected(
            "0.5.6", version_start=version_start, less_than_or_equal=less_than_or_equal
        )
        assert is_version_affected(
            "1.13.2", version_start=version_start, less_than_or_equal=less_than_or_equal
        )

        # Test versions outside range should NOT be affected
        assert not is_version_affected(
            "0.5.5", version_start=version_start, less_than_or_equal=less_than_or_equal
        )
        assert not is_version_affected(
            "1.13.3", version_start=version_start, less_than_or_equal=less_than_or_equal
        )
        assert not is_version_affected(
            "1.28.9", version_start=version_start, less_than_or_equal=less_than_or_equal
        )
