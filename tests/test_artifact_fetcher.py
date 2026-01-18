"""Tests for the artifact fetcher service."""

import json
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from cvec.core.config import Config
from cvec.services.artifact_fetcher import (
    ArtifactFetcher,
    ChecksumMismatchError,
    ManifestIncompatibleError,
    SUPPORTED_SCHEMA_VERSION,
)

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_config():
    """Create a config with temporary directories."""
    with tempfile.TemporaryDirectory() as tmpdir:
        config = Config(data_dir=Path(tmpdir))
        config.ensure_directories()
        yield config


@pytest.fixture
def fetcher(temp_config):
    """Create an ArtifactFetcher with temp config in quiet mode."""
    return ArtifactFetcher(config=temp_config, quiet=True)


@pytest.fixture
def mock_release():
    """Sample GitHub release data."""
    return {
        "tag_name": "v20260108",
        "assets": [
            {
                "name": "manifest.json",
                "browser_download_url": "https://example.com/manifest.json",
            },
            {
                "name": "cves.parquet",
                "browser_download_url": "https://example.com/cves.parquet",
            },
        ],
    }


@pytest.fixture
def mock_manifest():
    """Sample manifest data."""
    return {
        "schema_version": SUPPORTED_SCHEMA_VERSION,
        "generated_at": "2026-01-08T12:00:00Z",
        "release_status": "official",
        "files": [
            {"name": "cves.parquet", "sha256": "abc123"},
        ],
        "stats": {"total_cves": 1000},
    }


# =============================================================================
# ManifestIncompatibleError Tests
# =============================================================================


class TestManifestIncompatibleError:
    """Test ManifestIncompatibleError exception."""

    def test_error_message(self):
        """Test error message contains version info."""
        error = ManifestIncompatibleError(2, 1)
        assert "remote version 2" in str(error)
        assert "supported version 1" in str(error)
        assert error.remote_version == 2
        assert error.supported_version == 1


# =============================================================================
# ChecksumMismatchError Tests
# =============================================================================


class TestChecksumMismatchError:
    """Test ChecksumMismatchError exception."""

    def test_error_message(self):
        """Test error message is preserved."""
        error = ChecksumMismatchError("Checksum mismatch for test.parquet")
        assert "test.parquet" in str(error)


# =============================================================================
# ArtifactFetcher Init Tests
# =============================================================================


class TestArtifactFetcherInit:
    """Test ArtifactFetcher initialization."""

    def test_default_config(self):
        """Test that default config is used when not provided."""
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch("cvec.services.artifact_fetcher.get_config") as mock_get_config:
                mock_config = MagicMock()
                mock_config.data_dir = Path(tmpdir)
                mock_get_config.return_value = mock_config
                fetcher = ArtifactFetcher()
                assert fetcher.config == mock_config

    def test_custom_repo(self, temp_config):
        """Test custom repository can be specified."""
        fetcher = ArtifactFetcher(config=temp_config, repo="custom/repo")
        assert fetcher.repo == "custom/repo"

    def test_quiet_mode(self, temp_config):
        """Test quiet mode can be enabled."""
        fetcher = ArtifactFetcher(config=temp_config, quiet=True)
        assert fetcher.quiet is True

    def test_env_var_repo(self, temp_config):
        """Test repository can be set via environment variable."""
        with patch.dict("os.environ", {"CVEC_DB_REPO": "env/repo"}):
            fetcher = ArtifactFetcher(config=temp_config)
            assert fetcher.repo == "env/repo"


# =============================================================================
# API Call Tests
# =============================================================================


class TestGetLatestRelease:
    """Test _get_latest_release method."""

    def test_get_latest_release_success(self, fetcher, mock_release):
        """Test successful retrieval of latest release."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_release
            mock_get.return_value = mock_response

            result = fetcher._get_latest_release()

            assert result["tag_name"] == "v20260108"
            mock_get.assert_called_once()

    def test_get_latest_release_error(self, fetcher):
        """Test handling of API error."""
        with patch("requests.get") as mock_get:
            mock_get.return_value.raise_for_status.side_effect = Exception("API error")

            with pytest.raises(Exception):
                fetcher._get_latest_release()

    def test_get_latest_release_with_prerelease(self, fetcher):
        """Test retrieval of latest release including pre-releases."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            # Mock a list of releases where first one is a pre-release
            mock_response.json.return_value = [
                {
                    "tag_name": "v20260110-beta",
                    "prerelease": True,
                    "assets": [],
                },
                {
                    "tag_name": "v20260108",
                    "prerelease": False,
                    "assets": [],
                },
            ]
            mock_get.return_value = mock_response

            result = fetcher._get_latest_release(include_prerelease=True)

            assert result["tag_name"] == "v20260110-beta"
            assert result["prerelease"] is True
            # Should call /releases endpoint, not /releases/latest
            assert "/releases/latest" not in mock_get.call_args[0][0]

    def test_get_latest_release_without_prerelease(self, fetcher, mock_release):
        """Test retrieval of latest official release only."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_release
            mock_get.return_value = mock_response

            result = fetcher._get_latest_release(include_prerelease=False)

            # Should use /releases/latest endpoint
            assert "/releases/latest" in mock_get.call_args[0][0]


class TestGetReleaseByTag:
    """Test _get_release_by_tag method."""

    def test_get_release_by_tag_success(self, fetcher, mock_release):
        """Test successful retrieval of release by tag."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = mock_release
            mock_get.return_value = mock_response

            result = fetcher._get_release_by_tag("v20260108")

            assert result["tag_name"] == "v20260108"


# =============================================================================
# Compatibility Tests
# =============================================================================


class TestCheckCompatibility:
    """Test check_compatibility method."""

    def test_compatible_version(self, fetcher, mock_manifest):
        """Test compatible manifest version."""
        result = fetcher.check_compatibility(mock_manifest)
        assert result is True

    def test_incompatible_version(self, fetcher):
        """Test incompatible manifest version raises error."""
        manifest = {"schema_version": SUPPORTED_SCHEMA_VERSION + 100}
        with pytest.raises(ManifestIncompatibleError) as exc_info:
            fetcher.check_compatibility(manifest)
        assert exc_info.value.remote_version == SUPPORTED_SCHEMA_VERSION + 100
        assert exc_info.value.supported_version == SUPPORTED_SCHEMA_VERSION


# =============================================================================
# Local Manifest Tests
# =============================================================================


class TestGetLocalManifest:
    """Test get_local_manifest method."""

    def test_no_local_manifest(self, fetcher):
        """Test when no local manifest exists."""
        result = fetcher.get_local_manifest()
        assert result is None

    def test_local_manifest_exists(self, fetcher, mock_manifest):
        """Test when local manifest exists."""
        manifest_path = fetcher.config.data_dir / "manifest.json"
        manifest_path.write_text(json.dumps(mock_manifest))

        result = fetcher.get_local_manifest()
        assert result is not None
        assert result["schema_version"] == mock_manifest["schema_version"]


# =============================================================================
# Needs Update Tests
# =============================================================================


class TestNeedsUpdate:
    """Test needs_update method."""

    def test_needs_update_no_local(self, fetcher, mock_manifest):
        """Test when no local manifest exists."""
        assert fetcher.needs_update(mock_manifest, "v20260108", False) is True

    def test_needs_update_older_local(self, fetcher, mock_manifest):
        """Test when local manifest is older."""
        local_manifest = {
            "schema_version": SUPPORTED_SCHEMA_VERSION,
            "generated_at": "2026-01-01T12:00:00Z",
            "release_tag": "v20260101",
            "release_status": "official",
        }
        manifest_path = fetcher.config.data_dir / "manifest.json"
        manifest_path.write_text(json.dumps(local_manifest))

        assert fetcher.needs_update(mock_manifest, "v20260108", False) is True

    def test_needs_update_newer_local(self, fetcher, mock_manifest):
        """Test when local manifest is newer."""
        local_manifest = {
            "schema_version": SUPPORTED_SCHEMA_VERSION,
            "generated_at": "2026-12-31T12:00:00Z",
            "release_tag": "v20260108",
            "release_status": "official",
        }
        manifest_path = fetcher.config.data_dir / "manifest.json"
        manifest_path.write_text(json.dumps(local_manifest))

        assert fetcher.needs_update(mock_manifest, "v20260108", False) is False

    def test_needs_update_switching_to_official(self, fetcher, mock_manifest):
        """Test switching from pre-release to official release."""
        local_manifest = {
            "schema_version": SUPPORTED_SCHEMA_VERSION,
            "generated_at": "2026-01-10T12:00:00Z",
            "release_tag": "v20260110-beta",
            "release_status": "prerelease",
        }
        manifest_path = fetcher.config.data_dir / "manifest.json"
        manifest_path.write_text(json.dumps(local_manifest))

        # Should update when switching from prerelease to official
        assert fetcher.needs_update(mock_manifest, "v20260108", False) is True

    def test_needs_update_switching_to_prerelease(self, fetcher):
        """Test switching from official to pre-release."""
        local_manifest = {
            "schema_version": SUPPORTED_SCHEMA_VERSION,
            "generated_at": "2026-01-08T12:00:00Z",
            "release_tag": "v20260108",
            "release_status": "official",
        }
        manifest_path = fetcher.config.data_dir / "manifest.json"
        manifest_path.write_text(json.dumps(local_manifest))

        # Remote manifest is a prerelease
        remote_manifest = {
            "schema_version": SUPPORTED_SCHEMA_VERSION,
            "generated_at": "2026-01-10T12:00:00Z",
            "release_status": "prerelease",
        }

        # Should update to pre-release when explicitly requested
        assert fetcher.needs_update(remote_manifest, "v20260110-beta", True) is True


# =============================================================================
# Fetch Manifest Tests
# =============================================================================


class TestFetchManifest:
    """Test fetch_manifest method."""

    def test_fetch_manifest_no_asset(self, fetcher, mock_release):
        """Test when manifest asset is not found."""
        release_no_manifest = {
            "tag_name": "v20260108",
            "assets": [],
        }
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.json.return_value = release_no_manifest
            mock_get.return_value = mock_response

            with pytest.raises(ValueError) as exc_info:
                fetcher.fetch_manifest()
            assert "No manifest.json found" in str(exc_info.value)


# =============================================================================
# Download File Tests
# =============================================================================


class TestDownloadFile:
    """Test _download_file method."""

    def test_download_file_success(self, fetcher):
        """Test successful file download."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.headers = {"content-length": "100"}
            mock_response.iter_content.return_value = [b"test content"]
            mock_get.return_value = mock_response

            dest_path = fetcher.config.data_dir / "test.txt"
            fetcher._download_file("https://example.com/test.txt", dest_path)

            assert dest_path.exists()
            assert dest_path.read_bytes() == b"test content"

    def test_download_file_checksum_mismatch(self, fetcher):
        """Test checksum mismatch raises error."""
        with patch("requests.get") as mock_get:
            mock_response = MagicMock()
            mock_response.headers = {"content-length": "100"}
            mock_response.iter_content.return_value = [b"test content"]
            mock_get.return_value = mock_response

            dest_path = fetcher.config.data_dir / "test.txt"
            with pytest.raises(ChecksumMismatchError):
                fetcher._download_file(
                    "https://example.com/test.txt",
                    dest_path,
                    expected_sha256="wrong_hash",
                )
            # File should be removed on checksum mismatch
            assert not dest_path.exists()
