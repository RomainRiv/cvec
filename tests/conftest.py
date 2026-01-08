"""Pytest fixtures for CVE analyzer tests."""

import json
import tempfile
from pathlib import Path
from typing import Generator

import polars as pl
import pytest

from cvec.core.config import Config

# =============================================================================
# Sample CVE Data - Real-world examples
# =============================================================================

SAMPLE_CVE_2022_2196 = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {
        "cveId": "CVE-2022-2196",
        "assignerOrgId": "14ed7db2-1595-443d-9d34-6215bf890778",
        "state": "PUBLISHED",
        "assignerShortName": "Google",
        "dateReserved": "2022-06-24T13:29:09.969Z",
        "datePublished": "2023-01-09T10:59:53.099Z",
        "dateUpdated": "2025-02-13T16:28:57.097Z",
    },
    "containers": {
        "cna": {
            "affected": [
                {
                    "defaultStatus": "unaffected",
                    "packageName": "KVM",
                    "product": "Linux Kernel",
                    "vendor": "Linux",
                    "versions": [
                        {
                            "lessThan": "6.2",
                            "status": "affected",
                            "version": "0",
                            "versionType": "custom",
                        }
                    ],
                }
            ],
            "descriptions": [
                {
                    "lang": "en",
                    "value": "A regression exists in the Linux Kernel within KVM.",
                }
            ],
            "metrics": [
                {
                    "cvssV3_1": {
                        "attackComplexity": "HIGH",
                        "attackVector": "LOCAL",
                        "availabilityImpact": "LOW",
                        "baseScore": 5.8,
                        "baseSeverity": "MEDIUM",
                        "confidentialityImpact": "LOW",
                        "integrityImpact": "HIGH",
                        "privilegesRequired": "LOW",
                        "scope": "UNCHANGED",
                        "userInteraction": "NONE",
                        "vectorString": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L",
                        "version": "3.1",
                    }
                }
            ],
            "problemTypes": [
                {
                    "descriptions": [
                        {
                            "cweId": "CWE-1188",
                            "description": "CWE-1188 Insecure Default Initialization",
                            "lang": "en",
                            "type": "CWE",
                        }
                    ]
                }
            ],
            "providerMetadata": {
                "orgId": "14ed7db2-1595-443d-9d34-6215bf890778",
                "shortName": "Google",
                "dateUpdated": "2023-05-03T00:06:59.149Z",
            },
            "references": [{"url": "https://kernel.dance/#2e7eab81425a"}],
            "title": "KVM nVMX Spectre v2 vulnerability",
        }
    },
}

# CVE with text severity (no CVSS)
SAMPLE_CVE_TEXT_SEVERITY = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {
        "cveId": "CVE-2016-7054",
        "assignerOrgId": "3a12439a-4ef3-4c79-92e6-6081a721f1e5",
        "state": "PUBLISHED",
        "assignerShortName": "openssl",
        "datePublished": "2017-05-04T00:00:00.000Z",
    },
    "containers": {
        "cna": {
            "affected": [
                {
                    "product": "OpenSSL",
                    "vendor": "OpenSSL",
                    "versions": [{"status": "affected", "version": "1.1.0"}],
                }
            ],
            "descriptions": [
                {"lang": "en", "value": "ChaCha20/Poly1305 heap-buffer-overflow"}
            ],
            "metrics": [{"other": {"content": {"value": "High"}, "type": "unknown"}}],
            "problemTypes": [
                {
                    "descriptions": [
                        {
                            "cweId": "CWE-119",
                            "description": "CWE-119 Buffer Errors",
                            "lang": "en",
                            "type": "CWE",
                        }
                    ]
                }
            ],
            "providerMetadata": {
                "orgId": "3a12439a-4ef3-4c79-92e6-6081a721f1e5",
                "shortName": "openssl",
            },
            "references": [{"url": "https://www.openssl.org/news/secadv/20161110.txt"}],
            "title": "ChaCha20/Poly1305 heap-buffer-overflow",
        }
    },
}

# CVE with no severity at all
SAMPLE_CVE_NO_SEVERITY = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {
        "cveId": "CVE-2023-0001",
        "assignerOrgId": "14ed7db2-4595-443d-9d34-6215bf890778",
        "state": "PUBLISHED",
        "assignerShortName": "test",
        "datePublished": "2023-01-01T00:00:00.000Z",
    },
    "containers": {
        "cna": {
            "affected": [{"product": "TestProduct", "vendor": "TestVendor"}],
            "descriptions": [
                {"lang": "en", "value": "Test vulnerability with no severity"}
            ],
            "providerMetadata": {
                "orgId": "14ed7db2-4595-443d-9d34-6215bf890778",
                "shortName": "test",
            },
            "references": [{"url": "https://example.com/advisory"}],
        }
    },
}

# CVE with ADP metrics
SAMPLE_CVE_WITH_ADP = {
    "dataType": "CVE_RECORD",
    "dataVersion": "5.1",
    "cveMetadata": {
        "cveId": "CVE-2024-1234",
        "assignerOrgId": "14ed7db2-4595-443d-9d34-6215bf890778",
        "state": "PUBLISHED",
        "assignerShortName": "test",
        "datePublished": "2024-06-01T00:00:00.000Z",
    },
    "containers": {
        "cna": {
            "affected": [{"product": "SomeProduct", "vendor": "SomeVendor"}],
            "descriptions": [{"lang": "en", "value": "Test with ADP metrics"}],
            "providerMetadata": {
                "orgId": "14ed7db2-4595-443d-9d34-6215bf890778",
                "shortName": "test",
            },
            "references": [{"url": "https://example.com/advisory"}],
        },
        "adp": [
            {
                "providerMetadata": {
                    "orgId": "134c704f-9b21-4f2e-91b3-4a467353bcc0",
                    "shortName": "CISA-ADP",
                },
                "metrics": [
                    {
                        "cvssV3_1": {
                            "attackComplexity": "LOW",
                            "attackVector": "NETWORK",
                            "availabilityImpact": "HIGH",
                            "baseScore": 9.8,
                            "baseSeverity": "CRITICAL",
                            "confidentialityImpact": "HIGH",
                            "integrityImpact": "HIGH",
                            "privilegesRequired": "NONE",
                            "scope": "UNCHANGED",
                            "userInteraction": "NONE",
                            "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                            "version": "3.1",
                        }
                    }
                ],
            }
        ],
    },
}


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def temp_data_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for test data."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def temp_config(temp_data_dir: Path) -> Config:
    """Create a Config pointing to temporary directories."""
    # Create subdirectories - Config will derive cve_dir from data_dir
    cve_dir = temp_data_dir / "cve_github" / "individual"
    cve_dir.mkdir(parents=True)

    config = Config(
        data_dir=temp_data_dir,
    )
    return config


@pytest.fixture
def sample_cve_files(temp_config: Config) -> Config:
    """Create sample CVE JSON files in temp directory."""
    # Create year directories and files
    for sample, year in [
        (SAMPLE_CVE_2022_2196, "2022"),
        (SAMPLE_CVE_TEXT_SEVERITY, "2016"),
        (SAMPLE_CVE_NO_SEVERITY, "2023"),
        (SAMPLE_CVE_WITH_ADP, "2024"),
    ]:
        year_dir = temp_config.cve_dir / year
        year_dir.mkdir(parents=True, exist_ok=True)

        cve_id = sample["cveMetadata"]["cveId"]
        filepath = year_dir / f"{cve_id}.json"
        with open(filepath, "w") as f:
            json.dump(sample, f)

    return temp_config


@pytest.fixture
def sample_parquet_data(temp_config: Config) -> Config:
    """Create sample Parquet files for search tests using the new normalized schema."""
    # CVEs table (main table)
    cves_data = [
        {
            "cve_id": "CVE-2022-2196",
            "state": "PUBLISHED",
            "assigner_org_id": "14ed7db2-1595-443d-9d34-6215bf890778",
            "assigner_short_name": "Google",
            "date_reserved": "2022-06-24T13:29:09.969Z",
            "date_published": "2023-01-09T10:59:53.099Z",
            "date_updated": "2025-02-13T16:28:57.097Z",
            "cna_title": "KVM nVMX Spectre v2 vulnerability",
        },
        {
            "cve_id": "CVE-2016-7054",
            "state": "PUBLISHED",
            "assigner_org_id": "3a12439a-4ef3-4c79-92e6-6081a721f1e5",
            "assigner_short_name": "openssl",
            "date_reserved": None,
            "date_published": "2017-05-04T00:00:00.000Z",
            "date_updated": None,
            "cna_title": "ChaCha20/Poly1305 heap-buffer-overflow",
        },
        {
            "cve_id": "CVE-2023-0001",
            "state": "PUBLISHED",
            "assigner_org_id": "14ed7db2-4595-443d-9d34-6215bf890778",
            "assigner_short_name": "test",
            "date_reserved": None,
            "date_published": "2023-01-01T00:00:00.000Z",
            "date_updated": None,
            "cna_title": None,
        },
        {
            "cve_id": "CVE-2024-1234",
            "state": "PUBLISHED",
            "assigner_org_id": "14ed7db2-4595-443d-9d34-6215bf890778",
            "assigner_short_name": "test",
            "date_reserved": None,
            "date_published": "2024-06-01T00:00:00.000Z",
            "date_updated": None,
            "cna_title": "Test with ADP",
        },
        {
            "cve_id": "CVE-2024-9999",
            "state": "REJECTED",
            "assigner_org_id": "14ed7db2-4595-443d-9d34-6215bf890778",
            "assigner_short_name": "test",
            "date_reserved": None,
            "date_published": "2024-07-01T00:00:00.000Z",
            "date_updated": None,
            "cna_title": "Rejected test CVE",
        },
    ]
    cves_df = pl.DataFrame(cves_data)
    cves_df.write_parquet(temp_config.cves_parquet)

    # Descriptions table
    descriptions_data = [
        {
            "cve_id": "CVE-2022-2196",
            "lang": "en",
            "value": "A regression exists in the Linux Kernel within KVM.",
            "source": "cna",
        },
        {
            "cve_id": "CVE-2016-7054",
            "lang": "en",
            "value": "ChaCha20/Poly1305 heap-buffer-overflow",
            "source": "cna",
        },
        {
            "cve_id": "CVE-2023-0001",
            "lang": "en",
            "value": "Test vulnerability with no severity",
            "source": "cna",
        },
        {
            "cve_id": "CVE-2024-1234",
            "lang": "en",
            "value": "Test with ADP metrics",
            "source": "cna",
        },
    ]
    descriptions_df = pl.DataFrame(descriptions_data)
    descriptions_df.write_parquet(temp_config.cve_descriptions_parquet)

    # Metrics table
    metrics_data = [
        {
            "cve_id": "CVE-2022-2196",
            "metric_type": "cvssV3_1",
            "source": "cna",
            "base_score": 5.8,
            "base_severity": "MEDIUM",
            "vector_string": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L",
            "attack_vector": "LOCAL",
            "attack_complexity": "HIGH",
            "privileges_required": "LOW",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "LOW",
            "integrity_impact": "HIGH",
            "availability_impact": "LOW",
            "exploit_maturity": None,
            "exploitability_score": None,
            "impact_score": None,
            "other_type": None,
            "other_content": None,
        },
        {
            "cve_id": "CVE-2016-7054",
            "metric_type": "other",
            "source": "cna",
            "base_score": None,
            "base_severity": "High",
            "vector_string": None,
            "attack_vector": None,
            "attack_complexity": None,
            "privileges_required": None,
            "user_interaction": None,
            "scope": None,
            "confidentiality_impact": None,
            "integrity_impact": None,
            "availability_impact": None,
            "exploit_maturity": None,
            "exploitability_score": None,
            "impact_score": None,
            "other_type": None,
            "other_content": None,
        },
        {
            "cve_id": "CVE-2024-1234",
            "metric_type": "cvssV3_1",
            "source": "adp:CISA-ADP",
            "base_score": 9.8,
            "base_severity": "CRITICAL",
            "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "attack_vector": "NETWORK",
            "attack_complexity": "LOW",
            "privileges_required": "NONE",
            "user_interaction": "NONE",
            "scope": "UNCHANGED",
            "confidentiality_impact": "HIGH",
            "integrity_impact": "HIGH",
            "availability_impact": "HIGH",
            "exploit_maturity": None,
            "exploitability_score": None,
            "impact_score": None,
            "other_type": None,
            "other_content": None,
        },
        # KEV entry for CVE-2024-1234
        {
            "cve_id": "CVE-2024-1234",
            "metric_type": "other",
            "source": "adp:CISA-ADP",
            "base_score": None,
            "base_severity": None,
            "vector_string": None,
            "attack_vector": None,
            "attack_complexity": None,
            "privileges_required": None,
            "user_interaction": None,
            "scope": None,
            "confidentiality_impact": None,
            "integrity_impact": None,
            "availability_impact": None,
            "exploit_maturity": None,
            "exploitability_score": None,
            "impact_score": None,
            "other_type": "kev",
            "other_content": '{"dateAdded": "2024-01-15", "reference": "https://cisa.gov/kev"}',
        },
        # SSVC entry for CVE-2024-1234
        {
            "cve_id": "CVE-2024-1234",
            "metric_type": "other",
            "source": "adp:CISA-ADP",
            "base_score": None,
            "base_severity": None,
            "vector_string": None,
            "attack_vector": None,
            "attack_complexity": None,
            "privileges_required": None,
            "user_interaction": None,
            "scope": None,
            "confidentiality_impact": None,
            "integrity_impact": None,
            "availability_impact": None,
            "exploit_maturity": None,
            "exploitability_score": None,
            "impact_score": None,
            "other_type": "ssvc",
            "other_content": '{"automatable": "Yes", "exploitation": "Active", "technicalImpact": "Total"}',
        },
    ]
    metrics_df = pl.DataFrame(metrics_data)
    metrics_df.write_parquet(temp_config.cve_metrics_parquet)

    # Products table
    products_data = [
        {
            "cve_id": "CVE-2022-2196",
            "product_id": 1,
            "vendor": "Linux",
            "product": "Linux Kernel",
            "package_name": "KVM",
            "cpes": None,
            "modules": None,
            "program_files": None,
            "program_routines": None,
            "platforms": None,
            "repo": None,
            "default_status": "unaffected",
            "source": "cna",
        },
        {
            "cve_id": "CVE-2016-7054",
            "product_id": 2,
            "vendor": "OpenSSL",
            "product": "OpenSSL",
            "package_name": None,
            "cpes": None,
            "modules": None,
            "program_files": None,
            "program_routines": None,
            "platforms": None,
            "repo": None,
            "default_status": None,
            "source": "cna",
        },
        {
            "cve_id": "CVE-2023-0001",
            "product_id": 3,
            "vendor": "TestVendor",
            "product": "TestProduct",
            "package_name": None,
            "cpes": None,
            "modules": None,
            "program_files": None,
            "program_routines": None,
            "platforms": None,
            "repo": None,
            "default_status": None,
            "source": "cna",
        },
        {
            "cve_id": "CVE-2024-1234",
            "product_id": 4,
            "vendor": "SomeVendor",
            "product": "SomeProduct",
            "package_name": None,
            "cpes": None,
            "modules": None,
            "program_files": None,
            "program_routines": None,
            "platforms": None,
            "repo": None,
            "default_status": None,
            "source": "cna",
        },
        # Product with regex special characters for exact matching test
        {
            "cve_id": "CVE-2024-9999",
            "product_id": 5,
            "vendor": "Test.Vendor (Inc.)",
            "product": "Product[v1.0]+",
            "package_name": None,
            "cpes": None,
            "modules": None,
            "program_files": None,
            "program_routines": None,
            "platforms": None,
            "repo": None,
            "default_status": None,
            "source": "cna",
        },
    ]
    products_df = pl.DataFrame(products_data)
    products_df.write_parquet(temp_config.cve_products_parquet)

    # Versions table
    versions_data = [
        {
            "cve_id": "CVE-2022-2196",
            "product_id": 1,
            "version": "0",
            "version_type": "custom",
            "status": "affected",
            "less_than": "6.2",
            "less_than_or_equal": None,
            "source": "cna",
        },
        {
            "cve_id": "CVE-2016-7054",
            "product_id": 2,
            "version": "1.1.0",
            "version_type": None,
            "status": "affected",
            "less_than": None,
            "less_than_or_equal": None,
            "source": "cna",
        },
    ]
    versions_df = pl.DataFrame(versions_data)
    versions_df.write_parquet(temp_config.cve_versions_parquet)

    # CWEs table
    cwe_data = [
        {
            "cve_id": "CVE-2022-2196",
            "cwe_id": "CWE-1188",
            "description": "CWE-1188 Insecure Default Initialization",
            "lang": "en",
            "type": "CWE",
            "source": "cna",
        },
        {
            "cve_id": "CVE-2016-7054",
            "cwe_id": "CWE-119",
            "description": "CWE-119 Buffer Errors",
            "lang": "en",
            "type": "CWE",
            "source": "cna",
        },
    ]
    cwe_df = pl.DataFrame(cwe_data)
    cwe_df.write_parquet(temp_config.cve_cwes_parquet)

    # References table
    references_data = [
        {
            "cve_id": "CVE-2022-2196",
            "url": "https://kernel.dance/#2e7eab81425a",
            "name": None,
            "tags": None,
            "source": "cna",
        },
        {
            "cve_id": "CVE-2016-7054",
            "url": "https://www.openssl.org/news/secadv/20161110.txt",
            "name": None,
            "tags": None,
            "source": "cna",
        },
        {
            "cve_id": "CVE-2023-0001",
            "url": "https://example.com/advisory",
            "name": None,
            "tags": None,
            "source": "cna",
        },
        {
            "cve_id": "CVE-2024-1234",
            "url": "https://example.com/advisory",
            "name": None,
            "tags": None,
            "source": "cna",
        },
    ]
    references_df = pl.DataFrame(references_data)
    references_df.write_parquet(temp_config.cve_references_parquet)

    # Credits table (empty for tests)
    credits_data: list[dict] = []
    credits_df = pl.DataFrame(
        credits_data,
        schema={
            "cve_id": pl.Utf8,
            "lang": pl.Utf8,
            "value": pl.Utf8,
            "type": pl.Utf8,
            "user_uuid": pl.Utf8,
            "source": pl.Utf8,
        },
    )
    credits_df.write_parquet(temp_config.cve_credits_parquet)

    # Tags table (empty for tests)
    tags_data: list[dict] = []
    tags_df = pl.DataFrame(
        tags_data,
        schema={
            "cve_id": pl.Utf8,
            "tag": pl.Utf8,
            "source": pl.Utf8,
        },
    )
    tags_df.write_parquet(temp_config.cve_tags_parquet)

    return temp_config


@pytest.fixture
def sample_parquet_data_with_embeddings(sample_parquet_data) -> Config:
    """Create sample Parquet files including embeddings for semantic search tests."""
    from cvec.services.embeddings import EMBEDDING_DIMENSION

    # Create embeddings for all CVEs in sample_parquet_data
    # Use simple normalized vectors for testing
    embeddings_data = {
        "cve_id": [
            "CVE-2022-2196",
            "CVE-2016-7054",
            "CVE-2023-0001",
            "CVE-2024-1234",
            "CVE-2024-9999",
        ],
        "embedding": [
            [1.0] * EMBEDDING_DIMENSION,  # First CVE - high similarity to query
            [0.8] * EMBEDDING_DIMENSION,
            [0.5] * EMBEDDING_DIMENSION,
            [0.3] * EMBEDDING_DIMENSION,
            [0.1] * EMBEDDING_DIMENSION,  # Last CVE - low similarity
        ],
    }
    embeddings_df = pl.DataFrame(embeddings_data)
    embeddings_df.write_parquet(sample_parquet_data.cve_embeddings_parquet)

    return sample_parquet_data


@pytest.fixture
def mock_metric_with_cvss() -> dict:
    """Sample metric dict with CVSS v3.1 score."""
    return {
        "cve_id": "CVE-2022-2196",
        "metric_type": "cvssV3_1",
        "source": "cna",
        "base_score": 5.8,
        "base_severity": "MEDIUM",
        "vector_string": "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:L/I:H/A:L",
    }


@pytest.fixture
def mock_metric_with_text_severity() -> dict:
    """Sample metric dict with text severity only."""
    return {
        "cve_id": "CVE-2016-7054",
        "metric_type": "other",
        "source": "cna",
        "base_score": None,
        "base_severity": "High",
        "vector_string": None,
    }


@pytest.fixture
def mock_metric_adp() -> dict:
    """Sample metric dict with ADP CVSS score."""
    return {
        "cve_id": "CVE-2024-1234",
        "metric_type": "cvssV3_1",
        "source": "adp:CISA-ADP",
        "base_score": 9.8,
        "base_severity": "CRITICAL",
        "vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    }
