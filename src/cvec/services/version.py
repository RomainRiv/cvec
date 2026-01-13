"""Version comparison utilities for CVE version range matching.

This module provides version comparison functionality to determine if a specific
version is affected by a CVE based on version range information.

Version Range Types (from CVE records):
    - version: The starting version of the affected range
    - less_than: Affected if version < this value
    - less_than_or_equal: Affected if version <= this value
    - status: "affected", "unaffected", or "unknown"

Version Comparison:
    Supports multiple version formats:
    - Semantic versioning (e.g., 1.2.3, 1.2.3-beta)
    - Numeric versions (e.g., 1, 1.2, 1.2.3.4)
    - Named versions with prefixes (e.g., v1.2.3)
    - Custom versions as best-effort string comparison
"""

import re
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class VersionInfo:
    """Parsed version information."""

    original: str
    parts: List[int]
    prerelease: Optional[str] = None
    build: Optional[str] = None

    def __lt__(self, other: "VersionInfo") -> bool:
        """Compare two versions."""
        # Compare numeric parts
        for a, b in zip(self.parts, other.parts):
            if a < b:
                return True
            elif a > b:
                return False

        # If all compared parts are equal, shorter version is "less"
        if len(self.parts) < len(other.parts):
            # Check if remaining parts are all zeros
            if all(p == 0 for p in other.parts[len(self.parts) :]):
                # Consider equal (e.g., 1.0 == 1.0.0)
                pass
            else:
                return True
        elif len(self.parts) > len(other.parts):
            if all(p == 0 for p in self.parts[len(other.parts) :]):
                pass
            else:
                return False

        # Handle prerelease (prerelease < release)
        if self.prerelease and not other.prerelease:
            return True
        if not self.prerelease and other.prerelease:
            return False
        if self.prerelease and other.prerelease:
            return self.prerelease < other.prerelease

        return False

    def __le__(self, other: "VersionInfo") -> bool:
        return self == other or self < other

    def __gt__(self, other: "VersionInfo") -> bool:
        return other < self

    def __ge__(self, other: "VersionInfo") -> bool:
        return self == other or self > other

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VersionInfo):
            return False

        # Pad to same length for comparison
        max_len = max(len(self.parts), len(other.parts))
        self_parts = self.parts + [0] * (max_len - len(self.parts))
        other_parts = other.parts + [0] * (max_len - len(other.parts))

        if self_parts != other_parts:
            return False

        return self.prerelease == other.prerelease


def parse_version(version_str: str) -> VersionInfo:
    """Parse a version string into comparable components.

    Handles various version formats:
    - 1.2.3 (semantic versioning)
    - 1.2.3-alpha (with prerelease)
    - 1.2.3+build (with build metadata)
    - v1.2.3 (with prefix)
    - 1.0a, 1.0b2 (letter suffixes)

    Args:
        version_str: Version string to parse.

    Returns:
        VersionInfo with parsed components.
    """
    if not version_str:
        return VersionInfo(original="", parts=[0])

    original = version_str
    version_str = version_str.strip()

    # Remove common prefixes
    if version_str.lower().startswith("v"):
        version_str = version_str[1:]

    # Handle build metadata (+...)
    build = None
    if "+" in version_str:
        version_str, build = version_str.split("+", 1)

    # Handle prerelease (-alpha, -beta, -rc, etc.)
    prerelease = None
    prerelease_patterns = [
        r"[-_](alpha|beta|rc|pre|dev|snapshot|nightly|canary|unstable)[-_.]?(\d*)",
        r"[-_](\d+[a-z]+\d*)",  # e.g., -1rc2
    ]

    for pattern in prerelease_patterns:
        match = re.search(pattern, version_str, re.IGNORECASE)
        if match:
            prerelease = match.group(0)
            version_str = version_str[: match.start()]
            break

    # Handle letter suffixes like 1.0a, 1.0b2
    letter_suffix_match = re.search(r"([a-z])(\d*)$", version_str, re.IGNORECASE)
    if letter_suffix_match and not prerelease:
        letter = letter_suffix_match.group(1).lower()
        num = letter_suffix_match.group(2)
        prerelease = f"-{letter}{num}"
        version_str = version_str[: letter_suffix_match.start()]

    # Parse numeric parts
    parts: List[int] = []
    for part in re.split(r"[._-]", version_str):
        # Extract leading numeric portion
        num_match = re.match(r"(\d+)", part)
        if num_match:
            parts.append(int(num_match.group(1)))
        elif part and parts:
            # Non-numeric after numbers, might be suffix
            if not prerelease:
                prerelease = f"-{part}"

    if not parts:
        parts = [0]

    return VersionInfo(
        original=original,
        parts=parts,
        prerelease=prerelease,
        build=build,
    )


def compare_versions(v1: str, v2: str) -> int:
    """Compare two version strings.

    Args:
        v1: First version string.
        v2: Second version string.

    Returns:
        -1 if v1 < v2
        0 if v1 == v2
        1 if v1 > v2
    """
    ver1 = parse_version(v1)
    ver2 = parse_version(v2)

    if ver1 < ver2:
        return -1
    elif ver1 > ver2:
        return 1
    return 0


def is_version_affected(
    check_version: str,
    version_start: Optional[str] = None,
    less_than: Optional[str] = None,
    less_than_or_equal: Optional[str] = None,
    status: Optional[str] = None,
) -> bool:
    """Check if a specific version is affected by a vulnerability.

    Logic:
    1. If status is "unaffected", return False
    2. If version_start is specified, check_version must be >= version_start
    3. If less_than is specified, check_version must be < less_than
    4. If less_than_or_equal is specified, check_version must be <= less_than_or_equal

    Args:
        check_version: The version to check.
        version_start: Start of affected range (inclusive).
        less_than: End of affected range (exclusive).
        less_than_or_equal: End of affected range (inclusive).
        status: Version status ("affected", "unaffected", "unknown").

    Returns:
        True if the version is affected, False otherwise.

    Examples:
        >>> is_version_affected("1.5", version_start="1.0", less_than="2.0")
        True
        >>> is_version_affected("2.5", version_start="1.0", less_than="2.0")
        False
        >>> is_version_affected("1.0", less_than_or_equal="1.0")
        True
    """
    # If explicitly unaffected, return False
    if status and status.lower() == "unaffected":
        return False

    check = parse_version(check_version)

    # Check lower bound
    if version_start and version_start != "0":
        start = parse_version(version_start)
        if check < start:
            return False

    # Check upper bound (exclusive)
    if less_than:
        upper = parse_version(less_than)
        if not (check < upper):
            return False

    # Check upper bound (inclusive)
    if less_than_or_equal:
        upper = parse_version(less_than_or_equal)
        if not (check <= upper):
            return False

    # If we have range info and version is in range, it's affected
    # If no range info, we can't determine, so assume affected if status is "affected" or None
    if not less_than and not less_than_or_equal:
        # No upper bound specified - only exact version match or all versions affected
        if version_start:
            # Specific version start, no end = all versions from start
            return True
        # No bounds at all - can't determine, assume affected if status indicates
        if status and status.lower() in ("affected", "unknown"):
            return True
        if status is None:
            # No status, no bounds - ambiguous, be conservative
            return True

    return True


def version_in_range(
    version: str,
    ranges: List[dict],
) -> Tuple[bool, Optional[str]]:
    """Check if a version falls within any of the given ranges.

    Args:
        version: Version to check.
        ranges: List of range dictionaries with keys:
            - version: Start version
            - less_than: Upper bound (exclusive)
            - less_than_or_equal: Upper bound (inclusive)
            - status: "affected", "unaffected", "unknown"

    Returns:
        Tuple of (is_affected, status_reason).
        status_reason explains why (e.g., "in range 1.0 - 2.0").
    """
    is_affected = False
    reason = None

    for range_info in ranges:
        version_start = range_info.get("version")
        less_than = range_info.get("less_than")
        less_than_or_equal = range_info.get("less_than_or_equal")
        status = range_info.get("status")

        # Check if version is in this range
        in_range = False
        check_ver = parse_version(version)

        # Lower bound check
        if version_start and version_start != "0":
            start_ver = parse_version(version_start)
            if check_ver < start_ver:
                continue

        # Upper bound check
        if less_than:
            upper = parse_version(less_than)
            if check_ver >= upper:
                continue
            in_range = True
            reason = f"in range {version_start or '*'} to <{less_than}"
        elif less_than_or_equal:
            upper = parse_version(less_than_or_equal)
            if check_ver > upper:
                continue
            in_range = True
            reason = f"in range {version_start or '*'} to <={less_than_or_equal}"
        else:
            # No upper bound, check if exact match or open-ended
            in_range = True
            if version_start:
                reason = f"version >= {version_start}"
            else:
                reason = "all versions"

        if in_range:
            # Check status
            if status and status.lower() == "unaffected":
                # Explicitly unaffected in this range
                continue
            is_affected = True
            break

    return is_affected, reason
