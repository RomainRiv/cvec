"""Download service for CVE, CWE, and CAPEC data."""

import os
import zipfile
from pathlib import Path
from typing import Optional

import requests
from tqdm import tqdm

from cvec.core.config import Config, get_config

# Data source URLs
CAPEC_URL = "https://capec.mitre.org/data/xml/capec_latest.xml"
CWE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
CVE_GITHUB_URL = "https://github.com/CVEProject/cvelistV5/archive/refs/heads/main.zip"


class DownloadService:
    """Service for downloading CVE-related data from various sources."""

    def __init__(self, config: Optional[Config] = None, quiet: bool = False):
        """Initialize the download service.

        Args:
            config: Configuration instance. Uses default if not provided.
            quiet: If True, suppress progress output.
        """
        self.config = config or get_config()
        self.quiet = quiet
        self.config.ensure_directories()

    def _download_with_progress(
        self, url: str, dest_path: Path, desc: Optional[str] = None
    ) -> None:
        """Download a file with progress bar.

        Args:
            url: URL to download from.
            dest_path: Destination file path.
            desc: Description for progress bar.
        """
        response = requests.get(url, stream=True)
        response.raise_for_status()
        total = int(response.headers.get("content-length", 0))

        dest_path.parent.mkdir(parents=True, exist_ok=True)

        if self.quiet:
            with open(dest_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
        else:
            with (
                open(dest_path, "wb") as f,
                tqdm(
                    total=total, unit="B", unit_scale=True, desc=desc or dest_path.name
                ) as pbar,
            ):
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        pbar.update(len(chunk))

    def download_capec(self, url: Optional[str] = None) -> Path:
        """Download CAPEC attack patterns XML.

        Args:
            url: Optional custom URL. Uses default if not provided.

        Returns:
            Path to the downloaded file.
        """
        url = url or CAPEC_URL
        dest_path = self.config.capec_xml

        if not self.quiet:
            print(f"Downloading CAPEC from {url}")

        self._download_with_progress(url, dest_path, "CAPEC")

        if not self.quiet:
            print(f"CAPEC saved to {dest_path}")

        return dest_path

    def download_cwe(self, url: Optional[str] = None) -> Path:
        """Download and extract CWE weakness enumeration XML.

        Args:
            url: Optional custom URL. Uses default if not provided.

        Returns:
            Path to the extracted XML file.
        """
        url = url or CWE_URL
        dest_path = self.config.cwe_xml
        temp_zip = dest_path.with_suffix(".zip.tmp")

        if not self.quiet:
            print(f"Downloading CWE from {url}")

        self._download_with_progress(url, temp_zip, "CWE")

        # Extract XML from zip
        with zipfile.ZipFile(temp_zip) as z:
            xml_files = [name for name in z.namelist() if name.endswith(".xml")]
            if not xml_files:
                raise ValueError("No XML file found in CWE zip archive")

            with z.open(xml_files[0]) as source, open(dest_path, "wb") as target:
                target.write(source.read())

        temp_zip.unlink()

        if not self.quiet:
            print(f"CWE saved to {dest_path}")

        return dest_path

    def download_cves(
        self, url: Optional[str] = None, years: Optional[int] = None
    ) -> Path:
        """Download CVE data from GitHub cvelistV5 repository.

        Downloads the full repository as a zip file.

        Args:
            url: Optional custom URL. Uses default if not provided.
            years: Number of years to include (used during extraction, not download).

        Returns:
            Path to the downloaded zip file.
        """
        url = url or CVE_GITHUB_URL
        dest_path = self.config.cve_zip

        if not self.quiet:
            print(f"Downloading CVEs from {url}")

        self._download_with_progress(url, dest_path, "cvelistV5")

        if not self.quiet:
            print(f"CVE archive saved to {dest_path}")

        return dest_path

    def extract_cves(self, years: Optional[int] = None) -> Path:
        """Extract CVE files from the downloaded zip archive.

        Organizes CVEs by year and optionally filters to recent years.

        Args:
            years: Number of years to include. If None, uses config default.

        Returns:
            Path to the extraction directory.
        """
        zip_path = self.config.cve_zip
        dest_dir = self.config.cve_dir

        if not zip_path.exists():
            raise FileNotFoundError(
                f"CVE zip not found at {zip_path}. Run download_cves() first."
            )

        start_year, end_year = self.config.get_year_range(years)

        if not self.quiet:
            print(f"Extracting CVEs for years {start_year}-{end_year} to {dest_dir}")

        with zipfile.ZipFile(zip_path, "r") as z:
            namelist = z.namelist()
            if not namelist:
                raise ValueError("Zip file is empty")

            root_dir = os.path.commonpath(namelist)

            # Find all JSON files
            json_members = [
                m
                for m in z.infolist()
                if not m.is_dir() and m.filename.endswith(".json")
            ]

            if not self.quiet:
                print(f"Found {len(json_members)} JSON files in archive")

            extracted_count = 0
            iterator = (
                tqdm(json_members, desc="Extracting", unit="file")
                if not self.quiet
                else json_members
            )

            for member_info in iterator:
                relative_path = member_info.filename[len(root_dir) + 1 :]
                file_name = os.path.basename(relative_path)

                # Extract year from path
                year = None
                path_parts = relative_path.split(os.sep)
                for part in path_parts:
                    if part.isdigit() and len(part) == 4:
                        year = int(part)
                        break

                # Skip if outside year range
                if year is not None and (year < start_year or year > end_year):
                    continue

                # Determine target path
                if year:
                    year_dir = dest_dir / str(year)
                    year_dir.mkdir(parents=True, exist_ok=True)
                    target_path = year_dir / file_name
                else:
                    dest_dir.mkdir(parents=True, exist_ok=True)
                    target_path = dest_dir / file_name

                with z.open(member_info) as source, open(target_path, "wb") as target:
                    target.write(source.read())

                extracted_count += 1

        if not self.quiet:
            print(f"Extracted {extracted_count} CVE files to {dest_dir}")

        return dest_dir

    def download_all(self, years: Optional[int] = None) -> dict:
        """Download all data sources.

        Args:
            years: Number of years of CVE data to include.

        Returns:
            Dictionary with paths to all downloaded files.
        """
        results = {}

        results["capec"] = self.download_capec()
        results["cwe"] = self.download_cwe()
        results["cve_zip"] = self.download_cves()
        results["cve_dir"] = self.extract_cves(years)

        return results
