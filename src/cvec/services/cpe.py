"""CPE (Common Platform Enumeration) parsing and matching utilities.

This module provides utilities for working with CPE strings in both 2.2 and 2.3 formats.
It supports parsing CPE strings into components and matching them against product data.

CPE 2.3 Format:
    cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>

CPE 2.2 Format:
    cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>

Where:
    - part: a=application, o=operating system, h=hardware
    - vendor: Vendor name
    - product: Product name
    - version: Version string
    - Other fields are optional
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple, List


class CPEPart(Enum):
    """CPE part type."""

    APPLICATION = "a"
    OPERATING_SYSTEM = "o"
    HARDWARE = "h"
    ANY = "*"
    NA = "-"


@dataclass
class CPEComponents:
    """Parsed components from a CPE string."""

    part: Optional[str] = None
    vendor: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    update: Optional[str] = None
    edition: Optional[str] = None
    language: Optional[str] = None
    sw_edition: Optional[str] = None  # CPE 2.3 only
    target_sw: Optional[str] = None  # CPE 2.3 only
    target_hw: Optional[str] = None  # CPE 2.3 only
    other: Optional[str] = None  # CPE 2.3 only

    # Original string and format
    original: str = ""
    format: str = "2.3"

    def matches_product(
        self,
        vendor: Optional[str],
        product: Optional[str],
        case_insensitive: bool = True,
    ) -> bool:
        """Check if this CPE matches the given vendor/product.

        Args:
            vendor: Vendor name to match.
            product: Product name to match.
            case_insensitive: If True, use case-insensitive matching.

        Returns:
            True if this CPE matches the given vendor/product.
        """
        if case_insensitive:
            cpe_vendor = self.vendor.lower() if self.vendor else ""
            cpe_product = self.product.lower() if self.product else ""
            check_vendor = vendor.lower() if vendor else ""
            check_product = product.lower() if product else ""
        else:
            cpe_vendor = self.vendor or ""
            cpe_product = self.product or ""
            check_vendor = vendor or ""
            check_product = product or ""

        # Handle wildcards
        vendor_match = (
            not check_vendor
            or cpe_vendor == "*"
            or cpe_vendor == check_vendor
            or _wildcard_match(cpe_vendor, check_vendor)
        )

        product_match = (
            not check_product
            or cpe_product == "*"
            or cpe_product == check_product
            or _wildcard_match(cpe_product, check_product)
        )

        return vendor_match and product_match

    def to_search_terms(self) -> Tuple[Optional[str], Optional[str]]:
        """Extract vendor and product as search terms.

        Returns:
            Tuple of (vendor, product) for searching.
            Converts underscores/hyphens to spaces for better matching.
        """
        vendor = None
        product = None

        if self.vendor and self.vendor not in ("*", "-"):
            # Convert underscores to spaces, often used in CPEs
            vendor = self.vendor.replace("_", " ").replace("-", " ")

        if self.product and self.product not in ("*", "-"):
            product = self.product.replace("_", " ").replace("-", " ")

        return vendor, product


def _wildcard_match(pattern: str, text: str) -> bool:
    """Match a CPE wildcard pattern against text.

    CPE wildcards:
    - '*' matches any sequence
    - '?' matches any single character

    Args:
        pattern: Pattern with possible wildcards.
        text: Text to match against.

    Returns:
        True if pattern matches text.
    """
    if not pattern or pattern == "*":
        return True

    # Convert CPE wildcards to regex
    regex_pattern = ""
    i = 0
    while i < len(pattern):
        char = pattern[i]
        if char == "*":
            regex_pattern += ".*"
        elif char == "?":
            regex_pattern += "."
        elif char == "\\":
            # Escaped character
            if i + 1 < len(pattern):
                regex_pattern += re.escape(pattern[i + 1])
                i += 1
            else:
                regex_pattern += re.escape(char)
        else:
            regex_pattern += re.escape(char)
        i += 1

    try:
        return bool(re.fullmatch(regex_pattern, text, re.IGNORECASE))
    except re.error:
        return False


def _decode_cpe_value(value: str) -> str:
    """Decode a CPE 2.3 value, handling escapes and special characters.

    Args:
        value: CPE component value.

    Returns:
        Decoded value.
    """
    if value in ("*", "-"):
        return value

    # Handle URL-encoded characters common in CPE 2.2
    value = value.replace("%21", "!")
    value = value.replace("%22", '"')
    value = value.replace("%23", "#")
    value = value.replace("%24", "$")
    value = value.replace("%25", "%")
    value = value.replace("%26", "&")
    value = value.replace("%27", "'")
    value = value.replace("%28", "(")
    value = value.replace("%29", ")")
    value = value.replace("%2a", "*")
    value = value.replace("%2b", "+")
    value = value.replace("%2c", ",")
    value = value.replace("%2f", "/")
    value = value.replace("%3a", ":")
    value = value.replace("%3b", ";")
    value = value.replace("%3c", "<")
    value = value.replace("%3d", "=")
    value = value.replace("%3e", ">")
    value = value.replace("%3f", "?")
    value = value.replace("%40", "@")
    value = value.replace("%5b", "[")
    value = value.replace("%5c", "\\")
    value = value.replace("%5d", "]")
    value = value.replace("%5e", "^")
    value = value.replace("%60", "`")
    value = value.replace("%7b", "{")
    value = value.replace("%7c", "|")
    value = value.replace("%7d", "}")
    value = value.replace("%7e", "~")

    # Handle CPE 2.3 escapes (backslash followed by special char)
    # Just remove the backslash for matching purposes
    result = ""
    i = 0
    while i < len(value):
        if value[i] == "\\" and i + 1 < len(value):
            result += value[i + 1]
            i += 2
        else:
            result += value[i]
            i += 1

    return result


def parse_cpe(cpe_string: str) -> Optional[CPEComponents]:
    """Parse a CPE string into its components.

    Supports both CPE 2.2 and CPE 2.3 formats.

    Args:
        cpe_string: CPE string to parse.

    Returns:
        CPEComponents if valid, None if invalid.

    Examples:
        >>> parse_cpe("cpe:2.3:a:microsoft:windows:10:*:*:*:*:*:*:*")
        CPEComponents(part='a', vendor='microsoft', product='windows', version='10', ...)

        >>> parse_cpe("cpe:/a:microsoft:windows:10")
        CPEComponents(part='a', vendor='microsoft', product='windows', version='10', ...)
    """
    if not cpe_string:
        return None

    cpe_string = cpe_string.strip()

    # Detect format
    if cpe_string.startswith("cpe:2.3:"):
        return _parse_cpe_23(cpe_string)
    elif cpe_string.startswith("cpe:/"):
        return _parse_cpe_22(cpe_string)
    else:
        return None


def _parse_cpe_23(cpe_string: str) -> Optional[CPEComponents]:
    """Parse a CPE 2.3 formatted string.

    Format: cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>:<sw_edition>:<target_sw>:<target_hw>:<other>
    """
    if not cpe_string.startswith("cpe:2.3:"):
        return None

    # Remove prefix and split
    body = cpe_string[8:]  # Remove "cpe:2.3:"

    # Split on unescaped colons
    parts: List[str] = []
    current = ""
    i = 0
    while i < len(body):
        if body[i] == "\\" and i + 1 < len(body):
            current += body[i : i + 2]
            i += 2
        elif body[i] == ":":
            parts.append(current)
            current = ""
            i += 1
        else:
            current += body[i]
            i += 1
    parts.append(current)

    # CPE 2.3 should have exactly 11 components after "cpe:2.3:"
    if len(parts) < 4:
        return None

    # Pad to 11 components if needed
    while len(parts) < 11:
        parts.append("*")

    def decode(val: str) -> Optional[str]:
        if val in ("*", ""):
            return None
        if val == "-":
            return "-"
        return _decode_cpe_value(val)

    return CPEComponents(
        part=parts[0] if parts[0] not in ("*", "") else None,
        vendor=decode(parts[1]),
        product=decode(parts[2]),
        version=decode(parts[3]),
        update=decode(parts[4]) if len(parts) > 4 else None,
        edition=decode(parts[5]) if len(parts) > 5 else None,
        language=decode(parts[6]) if len(parts) > 6 else None,
        sw_edition=decode(parts[7]) if len(parts) > 7 else None,
        target_sw=decode(parts[8]) if len(parts) > 8 else None,
        target_hw=decode(parts[9]) if len(parts) > 9 else None,
        other=decode(parts[10]) if len(parts) > 10 else None,
        original=cpe_string,
        format="2.3",
    )


def _parse_cpe_22(cpe_string: str) -> Optional[CPEComponents]:
    """Parse a CPE 2.2 formatted string.

    Format: cpe:/<part>:<vendor>:<product>:<version>:<update>:<edition>:<language>
    """
    if not cpe_string.startswith("cpe:/"):
        return None

    # Remove prefix
    body = cpe_string[5:]  # Remove "cpe:/"

    # Split on colons
    parts = body.split(":")

    if len(parts) < 1:
        return None

    # First component might include part type (e.g., "a", "o", "h")
    first = parts[0]
    if first and first[0] in "aohAOH":
        part = first[0].lower()
        # Rest of first component is vendor
        vendor = first[1:] if len(first) > 1 else None
    else:
        part = None
        vendor = first if first else None

    def decode(idx: int) -> Optional[str]:
        if idx >= len(parts) or not parts[idx]:
            return None
        val = parts[idx]
        if val == "*":
            return None
        return _decode_cpe_value(val)

    return CPEComponents(
        part=part,
        vendor=(
            _decode_cpe_value(vendor)
            if vendor
            else decode(1) if len(parts) > 1 else None
        ),
        product=decode(1) if vendor else decode(2),
        version=decode(2) if vendor else decode(3),
        update=decode(3) if vendor else decode(4),
        edition=decode(4) if vendor else decode(5),
        language=decode(5) if vendor else decode(6),
        original=cpe_string,
        format="2.2",
    )


def is_valid_cpe(cpe_string: str) -> bool:
    """Check if a string is a valid CPE.

    Args:
        cpe_string: String to validate.

    Returns:
        True if valid CPE format, False otherwise.
    """
    return parse_cpe(cpe_string) is not None


def match_cpe_to_product(
    cpe: CPEComponents,
    vendor: Optional[str],
    product: Optional[str],
) -> bool:
    """Check if a parsed CPE matches the given vendor/product.

    Uses fuzzy matching to handle variations in naming.

    Args:
        cpe: Parsed CPE components.
        vendor: Vendor name to match.
        product: Product name to match.

    Returns:
        True if CPE matches vendor/product.
    """
    if not cpe:
        return False

    cpe_vendor = (
        cpe.vendor.lower().replace("_", " ").replace("-", " ") if cpe.vendor else ""
    )
    cpe_product = (
        cpe.product.lower().replace("_", " ").replace("-", " ") if cpe.product else ""
    )

    check_vendor = vendor.lower().replace("_", " ").replace("-", " ") if vendor else ""
    check_product = (
        product.lower().replace("_", " ").replace("-", " ") if product else ""
    )

    # Check for substring matches (flexible matching)
    vendor_match = (
        not check_vendor
        or cpe_vendor == "*"
        or check_vendor in cpe_vendor
        or cpe_vendor in check_vendor
    )

    product_match = (
        not check_product
        or cpe_product == "*"
        or check_product in cpe_product
        or cpe_product in check_product
    )

    return vendor_match and product_match
