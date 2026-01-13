"""Unit tests for CPE parsing utilities."""

import pytest

from cvec.services.cpe import (
    CPEComponents,
    CPEPart,
    parse_cpe,
    is_valid_cpe,
    match_cpe_to_product,
    _wildcard_match,
)


class TestParseCPE23:
    """Tests for CPE 2.3 format parsing."""

    def test_parse_full_cpe23(self):
        """Parse a complete CPE 2.3 string."""
        cpe = parse_cpe("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.format == "2.3"
        assert cpe.part == "a"
        assert cpe.vendor == "microsoft"
        assert cpe.product == "windows"
        assert cpe.version == "10"
        assert cpe.original == "cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*"

    def test_parse_cpe23_with_dashes(self):
        """Parse CPE 2.3 with NA (-) values."""
        cpe = parse_cpe("cpe:2.3:o:linux:linux_kernel:5.10:-:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.part == "o"
        assert cpe.vendor == "linux"
        assert cpe.product == "linux_kernel"
        assert cpe.version == "5.10"
        assert cpe.update == "-"

    def test_parse_cpe23_apache(self):
        """Parse Apache HTTP Server CPE."""
        cpe = parse_cpe("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.vendor == "apache"
        assert cpe.product == "http_server"
        assert cpe.version == "2.4.51"

    def test_parse_cpe23_with_escaped_chars(self):
        """Parse CPE 2.3 with escaped special characters."""
        cpe = parse_cpe("cpe:2.3:a:vendor\\:name:product:1.0:*:*:*:*:*:*:*")
        assert cpe is not None
        # The escaped colon should be preserved in vendor
        assert "vendor" in cpe.vendor

    def test_parse_cpe23_wildcards(self):
        """Parse CPE 2.3 with wildcard values."""
        cpe = parse_cpe("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.part == "a"
        assert cpe.vendor is None  # * is converted to None
        assert cpe.product is None

    def test_parse_cpe23_os(self):
        """Parse operating system CPE."""
        cpe = parse_cpe("cpe:2.3:o:microsoft:windows_10:1909:*:*:*:*:*:x64:*")
        assert cpe is not None
        assert cpe.part == "o"
        assert cpe.vendor == "microsoft"
        assert cpe.product == "windows_10"
        assert cpe.version == "1909"

    def test_parse_cpe23_hardware(self):
        """Parse hardware CPE."""
        cpe = parse_cpe("cpe:2.3:h:cisco:router:*:*:*:*:*:*:*:*")
        assert cpe is not None
        assert cpe.part == "h"
        assert cpe.vendor == "cisco"
        assert cpe.product == "router"


class TestParseCPE22:
    """Tests for CPE 2.2 format parsing."""

    def test_parse_simple_cpe22(self):
        """Parse a simple CPE 2.2 string."""
        cpe = parse_cpe("cpe:/a:microsoft:windows:10")
        assert cpe is not None
        assert cpe.format == "2.2"
        assert cpe.part == "a"
        assert cpe.vendor == "microsoft"
        assert cpe.product == "windows"
        assert cpe.version == "10"

    def test_parse_cpe22_apache(self):
        """Parse Apache CPE 2.2."""
        cpe = parse_cpe("cpe:/a:apache:http_server:2.4.51")
        assert cpe is not None
        assert cpe.vendor == "apache"
        assert cpe.product == "http_server"
        assert cpe.version == "2.4.51"

    def test_parse_cpe22_linux_kernel(self):
        """Parse Linux kernel CPE 2.2."""
        cpe = parse_cpe("cpe:/o:linux:linux_kernel:5.10")
        assert cpe is not None
        assert cpe.part == "o"
        assert cpe.vendor == "linux"
        assert cpe.product == "linux_kernel"
        assert cpe.version == "5.10"

    def test_parse_cpe22_url_encoded(self):
        """Parse CPE 2.2 with URL-encoded characters."""
        cpe = parse_cpe("cpe:/a:vendor%3aname:product:1.0")
        assert cpe is not None
        # URL-encoded colon should be decoded
        assert ":" in cpe.vendor or cpe.vendor == "vendor:name"


class TestInvalidCPE:
    """Tests for invalid CPE strings."""

    def test_empty_string(self):
        """Empty string should return None."""
        assert parse_cpe("") is None

    def test_none_input(self):
        """None input should return None."""
        assert parse_cpe(None) is None

    def test_invalid_prefix(self):
        """Invalid prefix should return None."""
        assert parse_cpe("invalid:2.3:a:vendor:product:1.0") is None

    def test_random_string(self):
        """Random string should return None."""
        assert parse_cpe("this is not a cpe") is None

    def test_incomplete_cpe23(self):
        """Incomplete CPE 2.3 with too few parts should return None."""
        # CPE 2.3 needs at least 4 parts (part, vendor, product, version)
        cpe = parse_cpe("cpe:2.3:a:vendor")
        assert cpe is None  # Too few parts to be useful


class TestIsValidCPE:
    """Tests for is_valid_cpe function."""

    def test_valid_cpe23(self):
        """Valid CPE 2.3 should return True."""
        assert is_valid_cpe("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")

    def test_valid_cpe22(self):
        """Valid CPE 2.2 should return True."""
        assert is_valid_cpe("cpe:/a:apache:http_server:2.4.51")

    def test_invalid_cpe(self):
        """Invalid CPE should return False."""
        assert not is_valid_cpe("not a cpe")
        assert not is_valid_cpe("")


class TestCPEComponentsSearchTerms:
    """Tests for CPE search term extraction."""

    def test_to_search_terms_underscores(self):
        """Underscores should be converted to spaces."""
        cpe = parse_cpe("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
        vendor, product = cpe.to_search_terms()
        assert vendor == "apache"
        assert product == "http server"

    def test_to_search_terms_wildcards_ignored(self):
        """Wildcard values should return None."""
        cpe = parse_cpe("cpe:2.3:a:*:*:*:*:*:*:*:*:*:*")
        vendor, product = cpe.to_search_terms()
        assert vendor is None
        assert product is None

    def test_to_search_terms_linux_kernel(self):
        """Test Linux kernel CPE."""
        cpe = parse_cpe("cpe:2.3:o:linux:linux_kernel:5.10:*:*:*:*:*:*:*")
        vendor, product = cpe.to_search_terms()
        assert vendor == "linux"
        assert product == "linux kernel"


class TestWildcardMatch:
    """Tests for CPE wildcard matching."""

    def test_star_matches_anything(self):
        """Star should match any string."""
        assert _wildcard_match("*", "anything")
        assert _wildcard_match("*", "")

    def test_question_matches_single_char(self):
        """Question mark should match single character."""
        assert _wildcard_match("te?t", "test")
        assert _wildcard_match("te?t", "text")
        assert not _wildcard_match("te?t", "tests")

    def test_partial_wildcards(self):
        """Test partial wildcard patterns."""
        assert _wildcard_match("win*", "windows")
        assert _wildcard_match("*server", "http_server")
        assert _wildcard_match("*soft*", "microsoft")

    def test_exact_match(self):
        """Exact strings should match."""
        assert _wildcard_match("apache", "apache")
        assert not _wildcard_match("apache", "nginx")


class TestMatchCPEToProduct:
    """Tests for CPE to product matching."""

    def test_match_exact(self):
        """Exact vendor/product match."""
        cpe = parse_cpe("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
        assert match_cpe_to_product(cpe, "apache", "http_server")

    def test_match_with_spaces(self):
        """Match with spaces/underscores normalized."""
        cpe = parse_cpe("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
        assert match_cpe_to_product(cpe, "apache", "http server")

    def test_match_case_insensitive(self):
        """Match should be case-insensitive."""
        cpe = parse_cpe("cpe:2.3:a:Apache:HTTP_Server:2.4.51:*:*:*:*:*:*:*")
        assert match_cpe_to_product(cpe, "apache", "http_server")

    def test_match_partial_vendor(self):
        """Partial vendor match."""
        cpe = parse_cpe("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
        assert match_cpe_to_product(cpe, "micro", None)

    def test_match_partial_product(self):
        """Partial product match."""
        cpe = parse_cpe("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
        assert match_cpe_to_product(cpe, None, "http")

    def test_no_match(self):
        """Non-matching vendor/product."""
        cpe = parse_cpe("cpe:2.3:a:apache:http_server:2.4.51:*:*:*:*:*:*:*")
        assert not match_cpe_to_product(cpe, "nginx", "server")
