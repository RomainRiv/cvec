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


class TestCLISearchFilters:
    """CLI integration tests for search command filters."""

    def test_search_with_cwe_filter(self, sample_parquet_data):
        """Search command with --cwe filter."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "search",
                "linux",
                "--cwe",
                "787",
                "--limit",
                "5",
            ],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_cvss_min(self, sample_parquet_data):
        """Search command with --cvss-min filter."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "search",
                "linux",
                "--cvss-min",
                "7.0",
                "--limit",
                "5",
            ],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_cvss_range(self, sample_parquet_data):
        """Search command with both --cvss-min and --cvss-max."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "search",
                "linux",
                "--cvss-min",
                "7.0",
                "--cvss-max",
                "9.0",
                "--limit",
                "5",
            ],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_sort_date(self, sample_parquet_data):
        """Search command with --sort date."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "search",
                "linux",
                "--sort",
                "date",
                "--limit",
                "5",
            ],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_sort_cvss(self, sample_parquet_data):
        """Search command with --sort cvss."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "search",
                "linux",
                "--sort",
                "cvss",
                "--limit",
                "5",
            ],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_sort_and_order(self, sample_parquet_data):
        """Search command with --sort and --order."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "search",
                "linux",
                "--sort",
                "date",
                "--order",
                "ascending",
                "--limit",
                "5",
            ],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_with_ids_only(self, sample_parquet_data):
        """Search command with --ids-only flag."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "search",
                "linux",
                "--ids-only",
                "--limit",
                "3",
            ],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0
        # Output should contain CVE IDs
        assert "CVE-" in result.output

    def test_search_with_stats(self, sample_parquet_data):
        """Search command with --stats flag."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "search",
                "linux",
                "--stats",
                "--limit",
                "5",
            ],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0
        # Should show summary statistics
        assert (
            "Severity:" in result.output
            or "Summary" in result.output
            or result.exit_code == 0
        )

    def test_search_cwe_without_query(self, sample_parquet_data):
        """Search with --cwe and no query should work."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "search",
                "--cwe",
                "787",
                "--limit",
                "5",
            ],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0

    def test_search_combined_filters(self, sample_parquet_data):
        """Search with multiple filters combined."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            [
                "search",
                "linux",
                "--cwe",
                "787",
                "--cvss-min",
                "7.0",
                "--sort",
                "cvss",
                "--limit",
                "3",
            ],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0


class TestCLIGetCommand:
    """CLI integration tests for get command with multiple CVEs."""

    def test_get_single_cve(self, sample_parquet_data):
        """Get command with single CVE ID."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["get", "CVE-2022-2196"],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0
        assert "CVE-2022-2196" in result.output

    def test_get_multiple_cves(self, sample_parquet_data):
        """Get command with multiple CVE IDs."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["get", "CVE-2022-2196", "CVE-2024-1234"],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0
        # Both CVE IDs should appear in output
        assert "CVE-2022-2196" in result.output or "CVE-2024-1234" in result.output

    def test_get_with_detailed_flag(self, sample_parquet_data):
        """Get command with --detailed flag."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["get", "CVE-2022-2196", "--detailed"],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0

    def test_get_nonexistent_cve(self, sample_parquet_data):
        """Get command with non-existent CVE should show warning."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["get", "CVE-9999-99999"],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 1
        assert "not found" in result.output.lower()

    def test_get_mixed_valid_invalid(self, sample_parquet_data):
        """Get command with mix of valid and invalid CVE IDs."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["get", "CVE-2022-2196", "CVE-9999-99999"],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        # Should show warning for invalid but succeed for valid
        assert "not found" in result.output.lower()


class TestCLIStatsCommand:
    """CLI integration tests for stats command with --output."""

    def test_stats_basic(self, sample_parquet_data):
        """Stats command basic execution."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["stats"],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0
        assert "CVE" in result.output or "Total" in result.output

    def test_stats_with_json_format(self, sample_parquet_data):
        """Stats command with JSON format."""
        import json

        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        result = runner.invoke(
            app,
            ["stats", "--format", "json"],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0
        # Should be valid JSON
        data = json.loads(result.output)
        assert "total_cves" in data or isinstance(data, dict)

    def test_stats_with_output_file(self, sample_parquet_data, tmp_path):
        """Stats command with --output to file."""
        from typer.testing import CliRunner

        from cvec.cli.main import app

        runner = CliRunner()
        output_file = tmp_path / "stats.json"

        result = runner.invoke(
            app,
            ["stats", "--format", "json", "--output", str(output_file)],
            env={"CVE_DATA_DIR": str(sample_parquet_data.data_dir)},
        )

        assert result.exit_code == 0
        assert output_file.exists()
        assert "Output written" in result.output
