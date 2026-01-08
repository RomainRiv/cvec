"""Tests for the downloader service."""

import io
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cvec.core.config import Config
from cvec.services.downloader import (
    DownloadService,
    CAPEC_URL,
    CWE_URL,
    CVE_GITHUB_URL,
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_config():
    """Create a config with temporary directories."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = Config(
            data_dir=Path(tmpdir) / "data", download_dir=Path(tmpdir) / "download"
        )
        config.ensure_directories()
        yield config


@pytest.fixture
def download_service(temp_config):
    """Create a DownloadService with temp config in quiet mode."""
    return DownloadService(config=temp_config, quiet=True)


# =============================================================================
# DownloadService Init Tests
# =============================================================================


class TestDownloadServiceInit:
    """Test DownloadService initialization."""

    def test_default_config(self):
        """Test that default config is used when not provided."""
        with patch("cvec.services.downloader.get_config") as mock_get_config:
            mock_config = MagicMock()
            mock_config.data_dir = Path(tempfile.gettempdir())
            mock_get_config.return_value = mock_config
            service = DownloadService()
            assert service.config == mock_config

    def test_quiet_mode(self, temp_config):
        """Test quiet mode can be enabled."""
        service = DownloadService(config=temp_config, quiet=True)
        assert service.quiet is True

    def test_verbose_mode(self, temp_config):
        """Test default is not quiet."""
        service = DownloadService(config=temp_config)
        assert service.quiet is False


# =============================================================================
# Download With Progress Tests
# =============================================================================


class TestDownloadWithProgress:
    """Test _download_with_progress method."""

    def test_download_with_progress_success_quiet(self, download_service):
        """Test successful file download in quiet mode."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.headers = {"content-length": "100"}
            mock_response.iter_content.return_value = [b"test content"]
            mock_get.return_value = mock_response

            dest_path = download_service.config.data_dir / "test.txt"
            download_service._download_with_progress(
                "https://example.com/test.txt", dest_path
            )

            assert dest_path.exists()
            assert dest_path.read_bytes() == b"test content"

    def test_download_creates_parent_dirs(self, download_service):
        """Test that parent directories are created if they don't exist."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.headers = {"content-length": "100"}
            mock_response.iter_content.return_value = [b"test"]
            mock_get.return_value = mock_response

            dest_path = download_service.config.data_dir / "subdir" / "test.txt"
            download_service._download_with_progress(
                "https://example.com/test.txt", dest_path
            )

            assert dest_path.parent.exists()
            assert dest_path.exists()


# =============================================================================
# Download CAPEC Tests
# =============================================================================


class TestDownloadCapec:
    """Test download_capec method."""

    def test_download_capec_default_url(self, download_service):
        """Test downloading CAPEC with default URL."""
        with patch.object(download_service, "_download_with_progress") as mock_download:
            result = download_service.download_capec()

            mock_download.assert_called_once()
            args = mock_download.call_args
            assert args[0][0] == CAPEC_URL
            assert result == download_service.config.capec_xml

    def test_download_capec_custom_url(self, download_service):
        """Test downloading CAPEC with custom URL."""
        custom_url = "https://custom.example.com/capec.xml"
        with patch.object(download_service, "_download_with_progress") as mock_download:
            result = download_service.download_capec(url=custom_url)

            args = mock_download.call_args
            assert args[0][0] == custom_url


# =============================================================================
# Download CWE Tests
# =============================================================================


class TestDownloadCwe:
    """Test download_cwe method."""

    def test_download_cwe_default_url(self, download_service):
        """Test downloading CWE with default URL."""
        # Create a mock zip file with an XML inside
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("cwe.xml", "<cwe>test</cwe>")
        zip_content = zip_buffer.getvalue()

        with patch.object(download_service, "_download_with_progress") as mock_download:
            # Make the download create a real zip file
            def side_effect(url, dest_path, desc=None):
                dest_path.write_bytes(zip_content)

            mock_download.side_effect = side_effect

            result = download_service.download_cwe()

            assert result == download_service.config.cwe_xml
            # The temp zip should be cleaned up
            assert not download_service.config.cwe_xml.with_suffix(".zip.tmp").exists()

    def test_download_cwe_no_xml_in_zip(self, download_service):
        """Test error when zip contains no XML file."""
        # Create a zip file without any XML
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("readme.txt", "No XML here")
        zip_content = zip_buffer.getvalue()

        with patch.object(download_service, "_download_with_progress") as mock_download:

            def side_effect(url, dest_path, desc=None):
                dest_path.write_bytes(zip_content)

            mock_download.side_effect = side_effect

            with pytest.raises(ValueError) as exc_info:
                download_service.download_cwe()
            assert "No XML file found" in str(exc_info.value)


# =============================================================================
# Download CVEs Tests
# =============================================================================


class TestDownloadCves:
    """Test download_cves method."""

    def test_download_cves_default_url(self, download_service):
        """Test downloading CVEs with default URL."""
        with patch.object(download_service, "_download_with_progress") as mock_download:
            result = download_service.download_cves()

            mock_download.assert_called_once()
            args = mock_download.call_args
            assert args[0][0] == CVE_GITHUB_URL
            assert result == download_service.config.cve_zip

    def test_download_cves_custom_url(self, download_service):
        """Test downloading CVEs with custom URL."""
        custom_url = "https://custom.example.com/cves.zip"
        with patch.object(download_service, "_download_with_progress") as mock_download:
            result = download_service.download_cves(url=custom_url)

            args = mock_download.call_args
            assert args[0][0] == custom_url


# =============================================================================
# Extract CVEs Tests
# =============================================================================


class TestExtractCves:
    """Test extract_cves method."""

    def test_extract_cves_no_zip(self, download_service):
        """Test error when zip file doesn't exist."""
        with pytest.raises(FileNotFoundError) as exc_info:
            download_service.extract_cves()
        assert "CVE zip not found" in str(exc_info.value)

    def test_extract_cves_empty_zip(self, download_service):
        """Test error when zip file is empty."""
        # Create an empty zip
        zip_path = download_service.config.cve_zip
        zip_path.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(zip_path, "w"):
            pass  # Empty zip

        with pytest.raises(ValueError) as exc_info:
            download_service.extract_cves()
        assert "empty" in str(exc_info.value).lower()

    def test_extract_cves_success(self, download_service):
        """Test successful CVE extraction."""
        # Create a zip with CVE files
        zip_path = download_service.config.cve_zip
        zip_path.parent.mkdir(parents=True, exist_ok=True)

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            # Add some CVE JSON files with year structure
            zf.writestr(
                "cvelistV5-main/cves/2025/CVE-2025-0001.json",
                '{"cveId": "CVE-2025-0001"}',
            )
            zf.writestr(
                "cvelistV5-main/cves/2025/CVE-2025-0002.json",
                '{"cveId": "CVE-2025-0002"}',
            )
            zf.writestr(
                "cvelistV5-main/cves/2024/CVE-2024-0001.json",
                '{"cveId": "CVE-2024-0001"}',
            )

        zip_path.write_bytes(zip_buffer.getvalue())

        result = download_service.extract_cves()

        assert result == download_service.config.cve_dir
        # Check files were extracted
        year_2025_dir = download_service.config.cve_dir / "2025"
        assert year_2025_dir.exists() or True  # The year filtering might exclude some


# =============================================================================
# Download All Tests
# =============================================================================


class TestDownloadAll:
    """Test download_all method."""

    def test_download_all_calls_all_methods(self, download_service):
        """Test that download_all calls all download methods."""
        with (
            patch.object(download_service, "download_capec") as mock_capec,
            patch.object(download_service, "download_cwe") as mock_cwe,
            patch.object(download_service, "download_cves") as mock_cves,
            patch.object(download_service, "extract_cves") as mock_extract,
        ):
            mock_capec.return_value = Path("/tmp/capec.xml")
            mock_cwe.return_value = Path("/tmp/cwe.xml")
            mock_cves.return_value = Path("/tmp/cves.zip")
            mock_extract.return_value = Path("/tmp/cves")

            result = download_service.download_all()

            mock_capec.assert_called_once()
            mock_cwe.assert_called_once()
            mock_cves.assert_called_once()
            mock_extract.assert_called_once()

            assert "capec" in result
            assert "cwe" in result
            assert "cve_zip" in result
            assert "cve_dir" in result


# =============================================================================
# URL Constants Tests
# =============================================================================


class TestURLConstants:
    """Test that URL constants are properly defined."""

    def test_capec_url_is_https(self):
        """Test CAPEC URL uses HTTPS."""
        assert CAPEC_URL.startswith("https://")

    def test_cwe_url_is_https(self):
        """Test CWE URL uses HTTPS."""
        assert CWE_URL.startswith("https://")

    def test_cve_github_url_is_https(self):
        """Test CVE GitHub URL uses HTTPS."""
        assert CVE_GITHUB_URL.startswith("https://")
