"""Service for fetching pre-built parquet files from cvec-db GitHub releases."""

import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any, Optional

import requests
from rich.progress import (
    BarColumn,
    DownloadColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
    TransferSpeedColumn,
)

from cvec import MANIFEST_SCHEMA_VERSION
from cvec.core.config import Config, get_config

# Manifest schema version this cvec version supports
SUPPORTED_SCHEMA_VERSION = MANIFEST_SCHEMA_VERSION

# Default cvec-db repository
DEFAULT_CVEC_DB_REPO = "RomainRiv/cvec-db"  # Update with actual repo

# Files that require semantic search capability (optional)
SEMANTIC_FILES = {"cve_embeddings.parquet"}


class ManifestIncompatibleError(Exception):
    """Raised when the manifest schema version is incompatible."""

    def __init__(self, remote_version: int, supported_version: int):
        self.remote_version = remote_version
        self.supported_version = supported_version
        super().__init__(
            f"Incompatible parquet schema: remote version {remote_version}, "
            f"supported version {supported_version}. "
            f"Please update cvec to the latest version."
        )


class ChecksumMismatchError(Exception):
    """Raised when a downloaded file's checksum doesn't match."""

    pass


class ArtifactFetcher:
    """Service for downloading pre-built CVE parquet files from GitHub releases."""

    def __init__(
        self,
        config: Optional[Config] = None,
        quiet: bool = False,
        repo: Optional[str] = None,
    ):
        """Initialize the artifact fetcher.

        Args:
            config: Configuration instance. Uses default if not provided.
            quiet: If True, suppress progress output.
            repo: GitHub repository in "owner/repo" format.
        """
        self.config = config or get_config()
        self.quiet = quiet
        self.repo = repo or os.environ.get("CVEC_DB_REPO", DEFAULT_CVEC_DB_REPO)
        self.config.ensure_directories()

    def _get_latest_release(self, include_prerelease: bool = False) -> dict[str, Any]:
        """Get the latest release from the cvec-db repository.

        Args:
            include_prerelease: If True, include pre-releases in search.

        Returns:
            Release metadata including tag_name and assets.
        """
        if include_prerelease:
            # Get all releases and find the latest (including pre-releases)
            url = f"https://api.github.com/repos/{self.repo}/releases"
            response = requests.get(url)
            response.raise_for_status()
            releases = response.json()
            if not releases:
                raise ValueError("No releases found")
            # First release in the list is the latest (including pre-releases)
            result: dict[str, Any] = releases[0]
            return result
        else:
            # Get the latest official release only
            url = f"https://api.github.com/repos/{self.repo}/releases/latest"
            response = requests.get(url)
            response.raise_for_status()
            latest_result: dict[str, Any] = response.json()
            return latest_result

    def _get_release_by_tag(self, tag: str) -> dict[str, Any]:
        """Get a specific release by tag.

        Args:
            tag: Release tag (e.g., "v20260106")

        Returns:
            Release metadata.
        """
        url = f"https://api.github.com/repos/{self.repo}/releases/tags/{tag}"
        response = requests.get(url)
        response.raise_for_status()
        result: dict[str, Any] = response.json()
        return result

    def _download_file(
        self,
        url: str,
        dest_path: Path,
        expected_sha256: Optional[str] = None,
        desc: Optional[str] = None,
    ) -> None:
        """Download a file with progress bar and optional checksum verification.

        Args:
            url: URL to download from.
            dest_path: Destination file path.
            expected_sha256: Expected SHA256 hash for verification.
            desc: Description for progress bar.
        """
        response = requests.get(url, stream=True)
        response.raise_for_status()
        total = int(response.headers.get("content-length", 0))

        dest_path.parent.mkdir(parents=True, exist_ok=True)

        sha256 = hashlib.sha256()

        if self.quiet:
            with open(dest_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        sha256.update(chunk)
        else:
            progress = Progress(
                TextColumn("{task.description}"),
                BarColumn(),
                DownloadColumn(),
                TransferSpeedColumn(),
                TimeRemainingColumn(),
            )
            with progress:
                task = progress.add_task(desc or dest_path.name, total=total)
                with open(dest_path, "wb") as f:
                    for chunk in response.iter_content(chunk_size=8192):
                        if chunk:
                            f.write(chunk)
                            sha256.update(chunk)
                            progress.update(task, advance=len(chunk))

        # Verify checksum
        if expected_sha256:
            actual_sha256 = sha256.hexdigest()
            if actual_sha256 != expected_sha256:
                dest_path.unlink()  # Remove corrupted file
                raise ChecksumMismatchError(
                    f"Checksum mismatch for {dest_path.name}: "
                    f"expected {expected_sha256}, got {actual_sha256}"
                )

    def fetch_manifest(
        self, tag: Optional[str] = None, include_prerelease: bool = False
    ) -> dict[str, Any]:
        """Fetch the manifest from a release.

        Args:
            tag: Release tag. If None, uses latest release.
            include_prerelease: If True, include pre-releases when fetching latest.

        Returns:
            Parsed manifest dictionary.
        """
        if tag:
            release = self._get_release_by_tag(tag)
        else:
            release = self._get_latest_release(include_prerelease=include_prerelease)

        # Find manifest asset
        manifest_asset = None
        for asset in release.get("assets", []):
            if asset["name"] == "manifest.json":
                manifest_asset = asset
                break

        if not manifest_asset:
            raise ValueError(
                f"No manifest.json found in release {release.get('tag_name')}"
            )

        # Download manifest
        response = requests.get(manifest_asset["browser_download_url"])
        response.raise_for_status()
        result: dict[str, Any] = response.json()
        return result

    def check_compatibility(self, manifest: dict) -> bool:
        """Check if the manifest is compatible with this version of cvec.

        Args:
            manifest: Parsed manifest dictionary.

        Returns:
            True if compatible.

        Raises:
            ManifestIncompatibleError: If the schema version is incompatible.
        """
        schema_version = manifest.get("schema_version", 0)
        if schema_version != SUPPORTED_SCHEMA_VERSION:
            raise ManifestIncompatibleError(schema_version, SUPPORTED_SCHEMA_VERSION)
        return True

    def get_local_manifest(self) -> Optional[dict[str, Any]]:
        """Get the local manifest if it exists.

        Returns:
            Parsed manifest dictionary or None if not found.
        """
        manifest_path = self.config.data_dir / "manifest.json"
        if manifest_path.exists():
            result: dict[str, Any] = json.loads(manifest_path.read_text())
            return result
        return None

    def needs_update(
        self,
        remote_manifest: dict[str, Any],
        remote_tag: str,
        include_prerelease: bool,
    ) -> bool:
        """Check if local database needs to be updated.

        Args:
            remote_manifest: Remote manifest to compare against.
            remote_tag: Tag name of the remote release.
            include_prerelease: Whether user wants pre-releases.

        Returns:
            True if update is needed.
        """
        local_manifest = self.get_local_manifest()
        if not local_manifest:
            return True

        # Get release status from manifests
        remote_status = remote_manifest.get("release_status", "draft")
        local_status = local_manifest.get("release_status", "draft")

        # If user wants official but has pre-release/draft, update
        if (
            not include_prerelease
            and remote_status == "official"
            and local_status != "official"
        ):
            return True

        # If user wants pre-release but has different release, check by tag
        local_tag = local_manifest.get("release_tag")
        if local_tag and local_tag != remote_tag:
            # Different tags means we should update
            return True

        # Same tag/status, compare timestamps as fallback
        local_time = local_manifest.get("generated_at", "")
        remote_time = remote_manifest.get("generated_at", "")

        result: bool = remote_time > local_time
        return result

    def update(
        self,
        tag: Optional[str] = None,
        force: bool = False,
        include_prerelease: bool = False,
        include_embeddings: bool = False,
    ) -> dict:
        """Update local parquet files from the latest release.

        Args:
            tag: Specific release tag to download. If None, uses latest.
            force: If True, download even if local is up-to-date.
            include_prerelease: If True, include pre-releases when fetching latest.
            include_embeddings: If True, download embedding files for semantic search.

        Returns:
            Dictionary with update status and downloaded files.
        """
        if not self.quiet:
            print(f"Fetching release info from {self.repo}...")

        # Get release info
        if tag:
            release = self._get_release_by_tag(tag)
        else:
            release = self._get_latest_release(include_prerelease=include_prerelease)

        tag_name = release.get("tag_name", "unknown")

        if not self.quiet:
            print(f"Found release: {tag_name}")

        # Find and download manifest first
        manifest = self.fetch_manifest(tag, include_prerelease=include_prerelease)

        # Check compatibility
        self.check_compatibility(manifest)

        # Get release status from manifest
        release_status = manifest.get("release_status", "draft")
        is_prerelease = release_status == "prerelease"

        # Check if update is needed
        if not force and not self.needs_update(manifest, tag_name, include_prerelease):
            if not self.quiet:
                print("Local database is already up-to-date.")
            return {"status": "up-to-date", "tag": tag_name, "downloaded": []}

        # Build asset lookup
        assets_by_name = {asset["name"]: asset for asset in release.get("assets", [])}

        # Download parquet files with checksum verification
        downloaded = []
        skipped_semantic = []
        files_info = manifest.get("files", [])

        for file_info in files_info:
            file_name = file_info["name"]
            expected_sha256 = file_info.get("sha256")

            # Skip embedding files unless explicitly requested
            if file_name in SEMANTIC_FILES and not include_embeddings:
                skipped_semantic.append(file_name)
                continue

            if file_name not in assets_by_name:
                if not self.quiet:
                    print(f"Warning: {file_name} not found in release assets")
                continue

            asset = assets_by_name[file_name]
            dest_path = self.config.data_dir / file_name

            if not self.quiet:
                print(f"Downloading {file_name}...")

            self._download_file(
                asset["browser_download_url"],
                dest_path,
                expected_sha256=expected_sha256,
                desc=file_name,
            )
            downloaded.append(file_name)

        # Save manifest locally and store release tag for tracking
        manifest["release_tag"] = tag_name
        manifest_path = self.config.data_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2))
        downloaded.append("manifest.json")

        if not self.quiet:
            print(f"Successfully downloaded {len(downloaded)} files.")
            if skipped_semantic:
                print(
                    f"Skipped {len(skipped_semantic)} embedding file(s). "
                    "Use 'cvec db update --embeddings' to download or 'cvec db build extract-embeddings' to generate locally."
                )

        return {
            "status": "updated",
            "tag": tag_name,
            "is_prerelease": is_prerelease,
            "downloaded": downloaded,
            "skipped_semantic": skipped_semantic,
            "stats": manifest.get("stats", {}),
        }

    def status(self) -> dict:
        """Get the current status of the local database.

        Returns:
            Dictionary with local and remote status.
        """
        local_manifest = self.get_local_manifest()

        try:
            remote_manifest = self.fetch_manifest()
            remote_release = self._get_latest_release()
            remote_tag = remote_release.get("tag_name", "unknown")
            remote_available = True
        except Exception:
            remote_manifest = None
            remote_release = None
            remote_tag = "unknown"
            remote_available = False

        needs_update = False
        if remote_available and remote_manifest is not None:
            needs_update = local_manifest is None or self.needs_update(
                remote_manifest, remote_tag, False
            )

        return {
            "local": {
                "exists": local_manifest is not None,
                "manifest": local_manifest,
            },
            "remote": {
                "available": remote_available,
                "manifest": remote_manifest,
            },
            "needs_update": needs_update,
        }
