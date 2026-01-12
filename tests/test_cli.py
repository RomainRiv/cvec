"""Unit tests for CLI functions."""

from unittest.mock import MagicMock

import pytest

from cvec.cli.formatters import get_severity_info


class TestGetSeverity:
    """Tests for get_severity_info helper function using search_service.get_best_metric()."""

    def test_cvssv4_preferred(self):
        """CVSS v4.0 should be preferred over other versions."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV4_0",
            "source": "cna",
            "base_score": 8.5,
            "base_severity": "HIGH",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "8.5"
        assert version == "v4.0"
        assert numeric == 8.5

    def test_cvssv3_1_second(self):
        """CVSS v3.1 should be used when v4.0 not available."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_1",
            "source": "cna",
            "base_score": 7.5,
            "base_severity": "HIGH",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "7.5"
        assert version == "v3.1"
        assert numeric == 7.5

    def test_cvssv3_fallback(self):
        """CVSS v3.0 should be used when v3.1 not available."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_0",
            "source": "cna",
            "base_score": 7.0,
            "base_severity": "HIGH",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "7.0"
        assert version == "v3.0"
        assert numeric == 7.0

    def test_adp_cvss_with_asterisk(self):
        """ADP scores should be marked with asterisk."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_1",
            "source": "adp:CISA-ADP",
            "base_score": 9.8,
            "base_severity": "CRITICAL",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "9.8"
        assert version == "v3.1*"
        assert numeric == 9.8

    def test_cvssv2_fallback(self):
        """CVSS v2.0 should be used as last CVSS fallback."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV2_0",
            "source": "cna",
            "base_score": 5.0,
            "base_severity": "MEDIUM",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "5.0"
        assert version == "v2.0"
        assert numeric == 5.0

    def test_text_severity_fallback(self):
        """Text severity should return dash when metric only has base_severity but no score."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "other",
            "source": "cna",
            "base_score": None,
            "base_severity": "High",
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        # When there's no numeric score but there is severity text, show it
        assert score == "High"
        assert version == "text"
        assert numeric is None

    def test_no_metric_returns_dash(self):
        """No metric should return dashes."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = None
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "-"
        assert version == "-"
        assert numeric is None

    def test_no_service_returns_dash(self):
        """No search_service should return dashes."""
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, None)
        assert score == "-"
        assert version == "-"
        assert numeric is None

    def test_score_formatting(self):
        """Score should be formatted with one decimal place."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_1",
            "source": "cna",
            "base_score": 7.123456,
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "7.1"  # Rounded to one decimal
        assert numeric == 7.123456  # Original value preserved

    def test_zero_score(self):
        """Zero score should be displayed, not treated as missing."""
        mock_service = MagicMock()
        mock_service.get_best_metric.return_value = {
            "metric_type": "cvssV3_1",
            "source": "cna",
            "base_score": 0.0,
        }
        row = {"cve_id": "CVE-2024-1234"}
        score, version, numeric = get_severity_info(row, mock_service)
        assert score == "0.0"
        assert version == "v3.1"
        assert numeric == 0.0


class TestOutputFormat:
    """Tests for output format options."""

    def test_output_format_values(self):
        """OutputFormat should have expected values."""
        from cvec.cli.formatters import OutputFormat

        assert OutputFormat.JSON == "json"
        assert OutputFormat.TABLE == "table"
        assert OutputFormat.MARKDOWN == "markdown"


class TestCVEIDPattern:
    """Tests for CVE ID pattern matching."""

    def test_valid_cve_id_patterns(self):
        """Valid CVE ID formats should match."""
        from cvec.cli.main import CVE_ID_PATTERN

        # Standard formats
        assert CVE_ID_PATTERN.match("CVE-2024-1234") is not None
        assert CVE_ID_PATTERN.match("CVE-2024-12345") is not None
        assert CVE_ID_PATTERN.match("CVE-2024-123456") is not None

        # Case insensitive
        assert CVE_ID_PATTERN.match("cve-2024-1234") is not None
        assert CVE_ID_PATTERN.match("Cve-2024-1234") is not None

    def test_invalid_cve_id_patterns(self):
        """Invalid CVE ID formats should not match."""
        from cvec.cli.main import CVE_ID_PATTERN

        # Too few digits in sequence number
        assert CVE_ID_PATTERN.match("CVE-2024-123") is None

        # Missing prefix
        assert CVE_ID_PATTERN.match("2024-1234") is None

        # Wrong separator
        assert CVE_ID_PATTERN.match("CVE_2024_1234") is None

        # Non-numeric
        assert CVE_ID_PATTERN.match("CVE-ABCD-1234") is None

        # Product name that looks like CVE but isn't
        assert CVE_ID_PATTERN.match("CVE-viewer") is None


class TestCVEAutoDetect:
    """Tests for CVE ID auto-detection in search."""

    def test_is_cve_id_with_standard_format(self):
        """Standard CVE ID should be detected."""
        from cvec.cli.main import CVE_ID_PATTERN

        assert CVE_ID_PATTERN.match("CVE-2024-1234") is not None

    def test_is_not_cve_id_with_product_name(self):
        """Product names should not be detected as CVE IDs."""
        from cvec.cli.main import CVE_ID_PATTERN

        # These are product searches, not CVE IDs
        assert CVE_ID_PATTERN.match("openssl") is None
        assert CVE_ID_PATTERN.match("linux kernel") is None
        assert CVE_ID_PATTERN.match("apache") is None

    def test_is_not_cve_id_with_cwe(self):
        """CWE IDs should not be detected as CVE IDs."""
        from cvec.cli.main import CVE_ID_PATTERN

        assert CVE_ID_PATTERN.match("CWE-79") is None
        assert CVE_ID_PATTERN.match("CWE-1234") is None
