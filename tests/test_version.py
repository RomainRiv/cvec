"""Unit tests for version comparison utilities."""

import pytest

from cvec.services.version import (
    VersionInfo,
    parse_version,
    compare_versions,
    is_version_affected,
    version_in_range,
)


class TestParseVersion:
    """Tests for version parsing."""

    def test_simple_version(self):
        """Parse simple version number."""
        v = parse_version("1.2.3")
        assert v.parts == [1, 2, 3]
        assert v.prerelease is None

    def test_two_part_version(self):
        """Parse two-part version."""
        v = parse_version("1.2")
        assert v.parts == [1, 2]

    def test_single_number(self):
        """Parse single number version."""
        v = parse_version("5")
        assert v.parts == [5]

    def test_four_part_version(self):
        """Parse four-part version (Windows style)."""
        v = parse_version("10.0.19041.1234")
        assert v.parts == [10, 0, 19041, 1234]

    def test_version_with_v_prefix(self):
        """Parse version with v prefix."""
        v = parse_version("v1.2.3")
        assert v.parts == [1, 2, 3]

    def test_version_with_prerelease(self):
        """Parse version with prerelease suffix."""
        v = parse_version("1.2.3-beta")
        assert v.parts == [1, 2, 3]
        assert v.prerelease is not None
        assert "beta" in v.prerelease

    def test_version_with_alpha(self):
        """Parse version with alpha suffix."""
        v = parse_version("1.0.0-alpha.1")
        assert v.parts == [1, 0, 0]
        assert v.prerelease is not None

    def test_version_with_rc(self):
        """Parse version with rc suffix."""
        v = parse_version("2.0.0-rc1")
        assert v.parts == [2, 0, 0]
        assert v.prerelease is not None

    def test_version_with_build_metadata(self):
        """Parse version with build metadata."""
        v = parse_version("1.2.3+build.123")
        assert v.parts == [1, 2, 3]
        assert v.build == "build.123"

    def test_version_letter_suffix(self):
        """Parse version with letter suffix (e.g., 1.0a)."""
        v = parse_version("1.0a")
        assert v.parts == [1, 0]
        # Letter suffixes are now patch_suffix (post-release), not prerelease
        assert v.patch_suffix is not None
        assert "a" in v.patch_suffix

    def test_empty_version(self):
        """Empty version should default to 0."""
        v = parse_version("")
        assert v.parts == [0]

    def test_version_with_underscores(self):
        """Parse version with underscores (common in some projects)."""
        v = parse_version("1_2_3")
        assert v.parts == [1, 2, 3]


class TestVersionComparison:
    """Tests for version comparison."""

    def test_equal_versions(self):
        """Equal versions should be equal."""
        v1 = parse_version("1.2.3")
        v2 = parse_version("1.2.3")
        assert v1 == v2

    def test_equal_with_trailing_zeros(self):
        """1.0 should equal 1.0.0."""
        v1 = parse_version("1.0")
        v2 = parse_version("1.0.0")
        assert v1 == v2

    def test_less_than(self):
        """Test less than comparison."""
        v1 = parse_version("1.0.0")
        v2 = parse_version("2.0.0")
        assert v1 < v2

    def test_less_than_minor(self):
        """Test less than with minor version difference."""
        v1 = parse_version("1.1.0")
        v2 = parse_version("1.2.0")
        assert v1 < v2

    def test_less_than_patch(self):
        """Test less than with patch version difference."""
        v1 = parse_version("1.0.1")
        v2 = parse_version("1.0.2")
        assert v1 < v2

    def test_prerelease_less_than_release(self):
        """Prerelease should be less than release."""
        v1 = parse_version("1.0.0-beta")
        v2 = parse_version("1.0.0")
        assert v1 < v2

    def test_alpha_less_than_beta(self):
        """Alpha should be less than beta."""
        v1 = parse_version("1.0.0-alpha")
        v2 = parse_version("1.0.0-beta")
        assert v1 < v2

    def test_greater_than(self):
        """Test greater than comparison."""
        v1 = parse_version("2.0.0")
        v2 = parse_version("1.0.0")
        assert v1 > v2

    def test_compare_versions_function(self):
        """Test compare_versions helper function."""
        assert compare_versions("1.0.0", "2.0.0") == -1
        assert compare_versions("2.0.0", "1.0.0") == 1
        assert compare_versions("1.0.0", "1.0.0") == 0


class TestIsVersionAffected:
    """Tests for version range checking."""

    def test_affected_in_range(self):
        """Version in range should be affected."""
        assert is_version_affected(
            "1.5.0",
            version_start="1.0.0",
            less_than="2.0.0",
        )

    def test_not_affected_below_range(self):
        """Version below range should not be affected."""
        assert not is_version_affected(
            "0.9.0",
            version_start="1.0.0",
            less_than="2.0.0",
        )

    def test_not_affected_above_range(self):
        """Version above range should not be affected."""
        assert not is_version_affected(
            "2.5.0",
            version_start="1.0.0",
            less_than="2.0.0",
        )

    def test_affected_at_start(self):
        """Version at range start should be affected."""
        assert is_version_affected(
            "1.0.0",
            version_start="1.0.0",
            less_than="2.0.0",
        )

    def test_not_affected_at_less_than(self):
        """Version at less_than boundary should not be affected."""
        assert not is_version_affected(
            "2.0.0",
            version_start="1.0.0",
            less_than="2.0.0",
        )

    def test_affected_at_less_than_or_equal(self):
        """Version at less_than_or_equal boundary should be affected."""
        assert is_version_affected(
            "2.0.0",
            version_start="1.0.0",
            less_than_or_equal="2.0.0",
        )

    def test_explicitly_unaffected(self):
        """Status 'unaffected' should return False."""
        assert not is_version_affected(
            "1.5.0",
            version_start="1.0.0",
            less_than="2.0.0",
            status="unaffected",
        )

    def test_affected_with_status_affected(self):
        """Status 'affected' should return True when in range."""
        assert is_version_affected(
            "1.5.0",
            version_start="1.0.0",
            less_than="2.0.0",
            status="affected",
        )

    def test_no_upper_bound(self):
        """No upper bound with same major version means affected."""
        # Same major version - should be affected
        assert is_version_affected(
            "1.5.0",
            version_start="1.0.0",
        )
        # Different major version - should NOT be affected
        assert not is_version_affected(
            "99.0.0",
            version_start="1.0.0",
        )

    def test_only_less_than(self):
        """Only less_than specified."""
        assert is_version_affected("1.0.0", less_than="2.0.0")
        assert not is_version_affected("3.0.0", less_than="2.0.0")

    def test_only_less_than_or_equal(self):
        """Only less_than_or_equal specified."""
        assert is_version_affected("2.0.0", less_than_or_equal="2.0.0")
        assert not is_version_affected("2.0.1", less_than_or_equal="2.0.0")

    def test_version_start_zero(self):
        """Version start of '0' should be ignored."""
        assert is_version_affected(
            "0.0.1",
            version_start="0",
            less_than="1.0.0",
        )


class TestVersionInRange:
    """Tests for version range list checking."""

    def test_single_range_affected(self):
        """Version in single range should be affected."""
        ranges = [{"version": "1.0.0", "less_than": "2.0.0", "status": "affected"}]
        is_affected, reason = version_in_range("1.5.0", ranges)
        assert is_affected
        assert reason is not None

    def test_single_range_not_affected(self):
        """Version outside single range should not be affected."""
        ranges = [{"version": "1.0.0", "less_than": "2.0.0", "status": "affected"}]
        is_affected, _ = version_in_range("3.0.0", ranges)
        assert not is_affected

    def test_multiple_ranges_affected_in_second(self):
        """Version in second range should be affected."""
        ranges = [
            {"version": "1.0.0", "less_than": "2.0.0", "status": "affected"},
            {"version": "3.0.0", "less_than": "4.0.0", "status": "affected"},
        ]
        is_affected, _ = version_in_range("3.5.0", ranges)
        assert is_affected

    def test_unaffected_range_skipped(self):
        """Unaffected status in range should be skipped."""
        ranges = [
            {"version": "1.0.0", "less_than": "2.0.0", "status": "unaffected"},
        ]
        is_affected, _ = version_in_range("1.5.0", ranges)
        assert not is_affected

    def test_less_than_or_equal_range(self):
        """Test less_than_or_equal in range."""
        ranges = [
            {"version": "1.0.0", "less_than_or_equal": "2.0.0", "status": "affected"}
        ]
        is_affected, reason = version_in_range("2.0.0", ranges)
        assert is_affected
        assert "<=" in reason


class TestRealWorldVersions:
    """Tests with real-world version patterns."""

    def test_apache_httpd_versions(self):
        """Test Apache HTTP Server version ranges."""
        assert is_version_affected(
            "2.4.49",
            version_start="2.4.49",
            less_than="2.4.51",
        )
        assert not is_version_affected(
            "2.4.51",
            version_start="2.4.49",
            less_than="2.4.51",
        )

    def test_linux_kernel_versions(self):
        """Test Linux kernel version ranges."""
        assert is_version_affected(
            "5.15.10",
            version_start="5.0",
            less_than="5.16",
        )
        assert compare_versions("5.15.10", "5.16.0") == -1

    def test_openssl_versions(self):
        """Test OpenSSL version patterns."""
        assert compare_versions("1.1.1k", "1.1.1l") == -1
        assert compare_versions("3.0.0", "1.1.1") == 1

    def test_windows_build_numbers(self):
        """Test Windows build number comparison."""
        assert compare_versions("10.0.19041.1234", "10.0.19042.0") == -1
        assert compare_versions("10.0.19042.1000", "10.0.19041.9999") == 1
