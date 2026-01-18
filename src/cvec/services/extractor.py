"""CVE data extraction service - Lossless Parquet representation.

This module extracts CVE JSON data into a normalized set of Parquet files
that preserve all information from the original JSON while providing
efficient columnar storage and querying.

Parquet files produced:
- cves.parquet: Core CVE metadata (1:1 with CVE)
- cve_descriptions.parquet: All descriptions with language info (1:N)
- cve_metrics.parquet: CVSS metrics with full component breakdown (1:N)
- cve_products.parquet: Affected products (1:N)
- cve_versions.parquet: Version ranges per product (1:N)
- cve_cwes.parquet: CWE/problem types (1:N)
- cve_references.parquet: References with tags (1:N)
- cve_credits.parquet: Credits/acknowledgments (1:N)
- cve_tags.parquet: CVE-level tags (1:N)
"""

import concurrent.futures
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Any, Iterable, List, NamedTuple, Optional, Union

import polars as pl
from pydantic import BaseModel
from rich.progress import (
    BarColumn,
    Progress,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)

from cvec.core.config import Config, get_config
from cvec.models.cve_model import (
    CnaPublishedContainer,
    Containers,
    CveJsonRecordFormat,
    NoneScoreType,
)


def _get_iterable(obj: Any) -> Iterable[Any]:
    """Get an iterable from an object that may have .root or be a list itself."""
    if obj is None:
        return []
    if hasattr(obj, "root"):
        result: Iterable[Any] = obj.root
        return result
    if isinstance(obj, (list, tuple)):
        return obj
    return [obj]


def _get_value(obj: Any) -> Optional[str]:
    """Get string value from an object that may have .root or be a primitive."""
    if obj is None:
        return None

    # Recursively unwrap .root until we get to the actual value
    unwrapped = obj
    max_depth = 5
    depth = 0
    while hasattr(unwrapped, "root") and depth < max_depth:
        unwrapped = unwrapped.root
        depth += 1

    # Handle enum-like objects with _value_
    if hasattr(unwrapped, "_value_"):
        return str(unwrapped._value_)

    return str(unwrapped) if unwrapped is not None else None


# =============================================================================
# Data Models - Normalized CVE representation
# =============================================================================


class CVERecord(BaseModel):
    """Core CVE metadata - one record per CVE."""

    # Identifiers
    cve_id: str
    data_type: str  # CVE_RECORD
    data_version: str  # 5.0, 5.1

    # Metadata
    state: str  # PUBLISHED, REJECTED, RESERVED
    assigner_org_id: Optional[str] = None
    assigner_short_name: Optional[str] = None

    # Dates from cveMetadata
    date_reserved: Optional[str] = None
    date_published: Optional[str] = None
    date_updated: Optional[str] = None
    date_rejected: Optional[str] = None

    # CNA container metadata
    cna_date_public: Optional[str] = None
    cna_title: Optional[str] = None
    cna_provider_org_id: Optional[str] = None
    cna_provider_short_name: Optional[str] = None
    cna_provider_date_updated: Optional[str] = None

    # Source info
    source_discovery: Optional[str] = None
    source_defect: Optional[str] = None  # comma-separated if multiple

    # Aggregated fields for quick filtering (derived, but useful)
    has_cna_metrics: bool = False
    has_adp_metrics: bool = False
    has_affected: bool = False
    has_references: bool = False
    has_credits: bool = False


class CVEDescription(BaseModel):
    """CVE descriptions - multiple per CVE (different languages, sources)."""

    cve_id: str
    source: str  # "cna" or "adp:<short_name>"
    lang: str
    value: str
    supporting_media_type: Optional[str] = None  # e.g., "text/html"
    supporting_media_base64: Optional[bool] = None


class CVEMetric(BaseModel):
    """CVSS and other metrics - normalized with all component fields."""

    cve_id: str
    source: str  # "cna" or "adp:<short_name>"

    # Metric type
    metric_type: str  # "cvssV2_0", "cvssV3_0", "cvssV3_1", "cvssV4_0", "other", "ssvc"
    format: Optional[str] = None  # for "other" type, e.g., "CVSS"

    # Scores
    base_score: Optional[float] = None
    exploitability_score: Optional[float] = None
    impact_score: Optional[float] = None

    # Severity
    base_severity: Optional[str] = None
    vector_string: Optional[str] = None
    version: Optional[str] = None

    # CVSS v2 specific
    access_vector: Optional[str] = None  # v2
    access_complexity: Optional[str] = None  # v2
    authentication: Optional[str] = None  # v2

    # CVSS v3/v4 shared
    attack_vector: Optional[str] = None
    attack_complexity: Optional[str] = None
    privileges_required: Optional[str] = None
    user_interaction: Optional[str] = None
    scope: Optional[str] = None
    confidentiality_impact: Optional[str] = None
    integrity_impact: Optional[str] = None
    availability_impact: Optional[str] = None

    # CVSS v4 additional
    attack_requirements: Optional[str] = None
    vulnerable_system_confidentiality: Optional[str] = None
    vulnerable_system_integrity: Optional[str] = None
    vulnerable_system_availability: Optional[str] = None
    subsequent_system_confidentiality: Optional[str] = None
    subsequent_system_integrity: Optional[str] = None
    subsequent_system_availability: Optional[str] = None

    # "other" type content (for ssvc, text severity, etc.)
    other_type: Optional[str] = None  # e.g., "ssvc", "unknown"
    other_content: Optional[str] = None  # JSON-encoded content


class CVEProduct(BaseModel):
    """Affected products - one record per affected product entry."""

    cve_id: str
    source: str  # "cna" or "adp:<short_name>"
    product_id: str  # unique id within CVE for linking to versions

    vendor: Optional[str] = None
    product: Optional[str] = None
    package_name: Optional[str] = None
    collection_url: Optional[str] = None
    repo: Optional[str] = None
    modules: Optional[str] = None  # comma-separated
    program_files: Optional[str] = None  # comma-separated
    program_routines: Optional[str] = None  # comma-separated
    platforms: Optional[str] = None  # comma-separated
    default_status: Optional[str] = None
    cpes: Optional[str] = None  # comma-separated CPE strings
    package_url: Optional[str] = None  # Package URL (PURL) identifier


class CVEVersion(BaseModel):
    """Version ranges for affected products."""

    cve_id: str
    product_id: str  # links to CVEProduct

    version: Optional[str] = None
    version_type: Optional[str] = None
    status: Optional[str] = None  # affected, unaffected, unknown
    less_than: Optional[str] = None
    less_than_or_equal: Optional[str] = None

    # Changes within a version range
    changes: Optional[str] = None  # JSON-encoded list of {at, status}


class CVECWE(BaseModel):
    """CWE/problem type mappings."""

    cve_id: str
    source: str  # "cna" or "adp:<short_name>"
    cwe_id: Optional[str] = None
    cwe_type: str  # "CWE" or "text"
    lang: str
    description: str


class CVEReference(BaseModel):
    """References with tags."""

    cve_id: str
    source: str  # "cna" or "adp:<short_name>"
    url: str
    name: Optional[str] = None
    tags: Optional[str] = None  # comma-separated


class CVECredit(BaseModel):
    """Credits and acknowledgments."""

    cve_id: str
    source: str  # "cna" or "adp:<short_name>"
    lang: str
    value: str
    credit_type: Optional[str] = None
    user_uuid: Optional[str] = None


class CVETag(BaseModel):
    """CVE-level tags (x_legacyV4Record, x_generator, etc.)."""

    cve_id: str
    source: str  # "cna", "adp:<short_name>", or "metadata"
    tag_key: str
    tag_value: Optional[str] = None  # JSON-encoded if complex


class ExtractedData(NamedTuple):
    """Complete extracted data from a CVE."""

    cve: CVERecord
    descriptions: List[CVEDescription]
    metrics: List[CVEMetric]
    products: List[CVEProduct]
    versions: List[CVEVersion]
    cwes: List[CVECWE]
    references: List[CVEReference]
    credits: List[CVECredit]
    tags: List[CVETag]


class ExtractionError(NamedTuple):
    """Information about a CVE that failed to extract."""

    cve_id: str
    file_path: str
    error_type: str
    error_message: str


# Type alias for process result
ProcessResult = Union[ExtractedData, ExtractionError]


# =============================================================================
# Extraction Logic
# =============================================================================


def _extract_metrics(
    metrics_container: Any, cve_id: str, source: str
) -> List[CVEMetric]:
    """Extract all metrics from a metrics container."""
    results: List[CVEMetric] = []

    if not metrics_container:
        return results

    for met in _get_iterable(metrics_container):
        # CVSS v2
        if met.cvssV2_0 and met.cvssV2_0.baseScore:
            cvss = met.cvssV2_0
            results.append(
                CVEMetric(
                    cve_id=cve_id,
                    source=source,
                    metric_type="cvssV2_0",
                    base_score=(
                        float(cvss.baseScore.root)
                        if hasattr(cvss.baseScore, "root")
                        else float(cvss.baseScore)
                    ),
                    vector_string=(
                        str(cvss.vectorString)
                        if hasattr(cvss, "vectorString") and cvss.vectorString
                        else None
                    ),
                    version="2.0",
                    access_vector=(
                        _get_value(cvss.accessVector)
                        if hasattr(cvss, "accessVector")
                        else None
                    ),
                    access_complexity=(
                        _get_value(cvss.accessComplexity)
                        if hasattr(cvss, "accessComplexity")
                        else None
                    ),
                    authentication=(
                        _get_value(cvss.authentication)
                        if hasattr(cvss, "authentication")
                        else None
                    ),
                    confidentiality_impact=(
                        _get_value(cvss.confidentialityImpact)
                        if hasattr(cvss, "confidentialityImpact")
                        else None
                    ),
                    integrity_impact=(
                        _get_value(cvss.integrityImpact)
                        if hasattr(cvss, "integrityImpact")
                        else None
                    ),
                    availability_impact=(
                        _get_value(cvss.availabilityImpact)
                        if hasattr(cvss, "availabilityImpact")
                        else None
                    ),
                )
            )

        # CVSS v3.0
        if (
            met.cvssV3_0
            and met.cvssV3_0.baseScore
            and not isinstance(met.cvssV3_0.baseScore, NoneScoreType)
        ):
            cvss = met.cvssV3_0
            results.append(
                CVEMetric(
                    cve_id=cve_id,
                    source=source,
                    metric_type="cvssV3_0",
                    base_score=(
                        float(cvss.baseScore.value)
                        if hasattr(cvss.baseScore, "value")
                        else float(cvss.baseScore)
                    ),
                    base_severity=(
                        _get_value(cvss.baseSeverity)
                        if hasattr(cvss, "baseSeverity")
                        else None
                    ),
                    vector_string=(
                        str(cvss.vectorString)
                        if hasattr(cvss, "vectorString") and cvss.vectorString
                        else None
                    ),
                    version="3.0",
                    attack_vector=(
                        _get_value(cvss.attackVector)
                        if hasattr(cvss, "attackVector")
                        else None
                    ),
                    attack_complexity=(
                        _get_value(cvss.attackComplexity)
                        if hasattr(cvss, "attackComplexity")
                        else None
                    ),
                    privileges_required=(
                        _get_value(cvss.privilegesRequired)
                        if hasattr(cvss, "privilegesRequired")
                        else None
                    ),
                    user_interaction=(
                        _get_value(cvss.userInteraction)
                        if hasattr(cvss, "userInteraction")
                        else None
                    ),
                    scope=_get_value(cvss.scope) if hasattr(cvss, "scope") else None,
                    confidentiality_impact=(
                        _get_value(cvss.confidentialityImpact)
                        if hasattr(cvss, "confidentialityImpact")
                        else None
                    ),
                    integrity_impact=(
                        _get_value(cvss.integrityImpact)
                        if hasattr(cvss, "integrityImpact")
                        else None
                    ),
                    availability_impact=(
                        _get_value(cvss.availabilityImpact)
                        if hasattr(cvss, "availabilityImpact")
                        else None
                    ),
                )
            )

        # CVSS v3.1
        if (
            met.cvssV3_1
            and met.cvssV3_1.baseScore
            and not isinstance(met.cvssV3_1.baseScore, NoneScoreType)
        ):
            cvss = met.cvssV3_1
            results.append(
                CVEMetric(
                    cve_id=cve_id,
                    source=source,
                    metric_type="cvssV3_1",
                    base_score=(
                        float(cvss.baseScore.value)
                        if hasattr(cvss.baseScore, "value")
                        else float(cvss.baseScore)
                    ),
                    base_severity=(
                        _get_value(cvss.baseSeverity)
                        if hasattr(cvss, "baseSeverity")
                        else None
                    ),
                    vector_string=(
                        str(cvss.vectorString)
                        if hasattr(cvss, "vectorString") and cvss.vectorString
                        else None
                    ),
                    version="3.1",
                    attack_vector=(
                        _get_value(cvss.attackVector)
                        if hasattr(cvss, "attackVector")
                        else None
                    ),
                    attack_complexity=(
                        _get_value(cvss.attackComplexity)
                        if hasattr(cvss, "attackComplexity")
                        else None
                    ),
                    privileges_required=(
                        _get_value(cvss.privilegesRequired)
                        if hasattr(cvss, "privilegesRequired")
                        else None
                    ),
                    user_interaction=(
                        _get_value(cvss.userInteraction)
                        if hasattr(cvss, "userInteraction")
                        else None
                    ),
                    scope=_get_value(cvss.scope) if hasattr(cvss, "scope") else None,
                    confidentiality_impact=(
                        _get_value(cvss.confidentialityImpact)
                        if hasattr(cvss, "confidentialityImpact")
                        else None
                    ),
                    integrity_impact=(
                        _get_value(cvss.integrityImpact)
                        if hasattr(cvss, "integrityImpact")
                        else None
                    ),
                    availability_impact=(
                        _get_value(cvss.availabilityImpact)
                        if hasattr(cvss, "availabilityImpact")
                        else None
                    ),
                )
            )

        # CVSS v4.0
        if met.cvssV4_0 and met.cvssV4_0.root.baseScore:
            cvss = met.cvssV4_0.root
            results.append(
                CVEMetric(
                    cve_id=cve_id,
                    source=source,
                    metric_type="cvssV4_0",
                    base_score=(
                        float(cvss.baseScore.value)
                        if hasattr(cvss.baseScore, "value")
                        else float(cvss.baseScore)
                    ),
                    base_severity=(
                        _get_value(cvss.baseSeverity)
                        if hasattr(cvss, "baseSeverity")
                        else None
                    ),
                    vector_string=(
                        str(cvss.vectorString)
                        if hasattr(cvss, "vectorString") and cvss.vectorString
                        else None
                    ),
                    version="4.0",
                    attack_vector=(
                        _get_value(cvss.attackVector)
                        if hasattr(cvss, "attackVector")
                        else None
                    ),
                    attack_complexity=(
                        _get_value(cvss.attackComplexity)
                        if hasattr(cvss, "attackComplexity")
                        else None
                    ),
                    attack_requirements=(
                        _get_value(cvss.attackRequirements)
                        if hasattr(cvss, "attackRequirements")
                        else None
                    ),
                    privileges_required=(
                        _get_value(cvss.privilegesRequired)
                        if hasattr(cvss, "privilegesRequired")
                        else None
                    ),
                    user_interaction=(
                        _get_value(cvss.userInteraction)
                        if hasattr(cvss, "userInteraction")
                        else None
                    ),
                    vulnerable_system_confidentiality=(
                        _get_value(cvss.vulnConfidentialityImpact)
                        if hasattr(cvss, "vulnConfidentialityImpact")
                        else None
                    ),
                    vulnerable_system_integrity=(
                        _get_value(cvss.vulnIntegrityImpact)
                        if hasattr(cvss, "vulnIntegrityImpact")
                        else None
                    ),
                    vulnerable_system_availability=(
                        _get_value(cvss.vulnAvailabilityImpact)
                        if hasattr(cvss, "vulnAvailabilityImpact")
                        else None
                    ),
                    subsequent_system_confidentiality=(
                        _get_value(cvss.subConfidentialityImpact)
                        if hasattr(cvss, "subConfidentialityImpact")
                        else None
                    ),
                    subsequent_system_integrity=(
                        _get_value(cvss.subIntegrityImpact)
                        if hasattr(cvss, "subIntegrityImpact")
                        else None
                    ),
                    subsequent_system_availability=(
                        _get_value(cvss.subAvailabilityImpact)
                        if hasattr(cvss, "subAvailabilityImpact")
                        else None
                    ),
                )
            )

        # "other" metrics (SSVC, text severity, etc.)
        if hasattr(met, "other") and met.other:
            other = met.other
            other_type = (
                str(other.type) if hasattr(other, "type") and other.type else None
            )
            other_content = None
            base_severity = None

            if hasattr(other, "content") and other.content:
                if isinstance(other.content, dict):
                    # Extract text severity if present
                    sev_val = other.content.get("value")
                    if sev_val and isinstance(sev_val, str):
                        base_severity = sev_val
                    other_content = json.dumps(other.content)
                else:
                    other_content = str(other.content)

            results.append(
                CVEMetric(
                    cve_id=cve_id,
                    source=source,
                    metric_type="other",
                    other_type=other_type,
                    other_content=other_content,
                    base_severity=base_severity,
                )
            )

    return results


def _extract_products_and_versions(
    affected_container: Any, cve_id: str, source: str
) -> tuple[List[CVEProduct], List[CVEVersion]]:
    """Extract affected products and their version information."""
    products: List[CVEProduct] = []
    versions: List[CVEVersion] = []

    if not affected_container:
        return products, versions

    for idx, prod in enumerate(_get_iterable(affected_container)):
        # Generate unique product ID for linking versions
        product_id = f"{cve_id}:{source}:{idx}"

        vendor = str(prod.vendor) if prod.vendor else None
        product_name = str(prod.product) if prod.product else None
        package_name = (
            str(prod.packageName)
            if hasattr(prod, "packageName") and prod.packageName
            else None
        )

        # Collection URL
        collection_url = None
        if hasattr(prod, "collectionURL") and prod.collectionURL:
            collection_url = _get_value(prod.collectionURL)

        # Repo
        repo = None
        if hasattr(prod, "repo") and prod.repo:
            repo = _get_value(prod.repo)

        # Modules
        modules = None
        if hasattr(prod, "modules") and prod.modules:
            modules = ",".join([str(m) for m in _get_iterable(prod.modules)])

        # Program files
        program_files = None
        if hasattr(prod, "programFiles") and prod.programFiles:
            program_files = ",".join([str(f) for f in _get_iterable(prod.programFiles)])

        # Program routines
        program_routines = None
        if hasattr(prod, "programRoutines") and prod.programRoutines:
            routines = []
            for r in _get_iterable(prod.programRoutines):
                if hasattr(r, "name"):
                    routines.append(str(r.name))
            program_routines = ",".join(routines) if routines else None

        # Platforms
        platforms = None
        if hasattr(prod, "platforms") and prod.platforms:
            platforms = ",".join([str(p) for p in _get_iterable(prod.platforms)])

        # Default status
        default_status = None
        if hasattr(prod, "defaultStatus") and prod.defaultStatus:
            default_status = _get_value(prod.defaultStatus)

        # CPEs
        cpes = None
        if hasattr(prod, "cpes") and prod.cpes:
            cpe_list = [_get_value(c) for c in _get_iterable(prod.cpes)]
            cpes = ",".join([c for c in cpe_list if c])

        # Package URL (PURL)
        package_url = None
        if hasattr(prod, "packageURL") and prod.packageURL:
            package_url = _get_value(prod.packageURL)

        products.append(
            CVEProduct(
                cve_id=cve_id,
                source=source,
                product_id=product_id,
                vendor=vendor,
                product=product_name,
                package_name=package_name,
                collection_url=collection_url,
                repo=repo,
                modules=modules,
                program_files=program_files,
                program_routines=program_routines,
                platforms=platforms,
                default_status=default_status,
                cpes=cpes,
                package_url=package_url,
            )
        )

        # Extract versions
        if hasattr(prod, "versions") and prod.versions:
            for ver in _get_iterable(prod.versions):
                version_val = (
                    _get_value(ver.version)
                    if hasattr(ver, "version") and ver.version
                    else None
                )
                version_type = (
                    _get_value(ver.versionType)
                    if hasattr(ver, "versionType") and ver.versionType
                    else None
                )
                less_than = (
                    _get_value(ver.lessThan)
                    if hasattr(ver, "lessThan") and ver.lessThan
                    else None
                )
                less_than_or_equal = (
                    _get_value(ver.lessThanOrEqual)
                    if hasattr(ver, "lessThanOrEqual") and ver.lessThanOrEqual
                    else None
                )
                status = (
                    _get_value(ver.status)
                    if hasattr(ver, "status") and ver.status
                    else None
                )

                # Changes within version range
                changes = None
                if hasattr(ver, "changes") and ver.changes:
                    change_list = []
                    for ch in _get_iterable(ver.changes):
                        change_entry = {
                            "at": _get_value(ch.at) if hasattr(ch, "at") else None,
                            "status": (
                                _get_value(ch.status) if hasattr(ch, "status") else None
                            ),
                        }
                        change_list.append(change_entry)
                    if change_list:
                        changes = json.dumps(change_list)

                versions.append(
                    CVEVersion(
                        cve_id=cve_id,
                        product_id=product_id,
                        version=version_val,
                        version_type=version_type,
                        status=status,
                        less_than=less_than,
                        less_than_or_equal=less_than_or_equal,
                        changes=changes,
                    )
                )

    return products, versions


def _extract_cwes(
    problem_types_container: Any, cve_id: str, source: str
) -> List[CVECWE]:
    """Extract CWE/problem type mappings."""
    results: List[CVECWE] = []

    if not problem_types_container:
        return results

    for pt in _get_iterable(problem_types_container):
        if not hasattr(pt, "descriptions") or not pt.descriptions:
            continue

        for desc in _get_iterable(pt.descriptions):
            cwe_id = None
            cwe_type = "text"
            lang = "en"
            description = ""

            if hasattr(desc, "cweId") and desc.cweId:
                cwe_id = str(desc.cweId)
                cwe_type = "CWE"

            if hasattr(desc, "type") and desc.type:
                type_val = _get_value(desc.type)
                if type_val:
                    cwe_type = type_val

            if hasattr(desc, "lang") and desc.lang:
                lang = str(desc.lang)

            if hasattr(desc, "description") and desc.description:
                description = str(desc.description)

            results.append(
                CVECWE(
                    cve_id=cve_id,
                    source=source,
                    cwe_id=cwe_id,
                    cwe_type=cwe_type,
                    lang=lang,
                    description=description,
                )
            )

    return results


def _extract_references(
    references_container: Any, cve_id: str, source: str
) -> List[CVEReference]:
    """Extract references with tags."""
    results: List[CVEReference] = []

    if not references_container:
        return results

    for ref in _get_iterable(references_container):
        url = _get_value(ref.url) if hasattr(ref, "url") and ref.url else None
        if not url:
            continue

        name = _get_value(ref.name) if hasattr(ref, "name") and ref.name else None

        tags = None
        if hasattr(ref, "tags") and ref.tags:
            tag_values = [_get_value(t) for t in _get_iterable(ref.tags)]
            tags = ",".join([t for t in tag_values if t])

        results.append(
            CVEReference(
                cve_id=cve_id,
                source=source,
                url=url,
                name=name,
                tags=tags,
            )
        )

    return results


def _extract_credits(
    credits_container: Any, cve_id: str, source: str
) -> List[CVECredit]:
    """Extract credits and acknowledgments."""
    results: List[CVECredit] = []

    if not credits_container:
        return results

    for credit in _get_iterable(credits_container):
        value = (
            _get_value(credit.value)
            if hasattr(credit, "value") and credit.value
            else None
        )
        if not value:
            continue

        lang = str(credit.lang) if hasattr(credit, "lang") and credit.lang else "en"
        credit_type = (
            _get_value(credit.type) if hasattr(credit, "type") and credit.type else None
        )
        user_uuid = (
            _get_value(credit.user) if hasattr(credit, "user") and credit.user else None
        )

        results.append(
            CVECredit(
                cve_id=cve_id,
                source=source,
                lang=lang,
                value=value,
                credit_type=credit_type,
                user_uuid=user_uuid,
            )
        )

    return results


def _extract_descriptions(
    descriptions_container: Any, cve_id: str, source: str
) -> List[CVEDescription]:
    """Extract all descriptions."""
    results: List[CVEDescription] = []

    if not descriptions_container:
        return results

    for desc in _get_iterable(descriptions_container):
        lang = _get_value(desc.lang) if hasattr(desc, "lang") and desc.lang else "en"
        value = _get_value(desc.value) if hasattr(desc, "value") and desc.value else ""

        supporting_media_type = None
        supporting_media_base64 = None
        if hasattr(desc, "supportingMedia") and desc.supportingMedia:
            for media in _get_iterable(desc.supportingMedia):
                if hasattr(media, "type"):
                    supporting_media_type = _get_value(media.type)
                if hasattr(media, "base64"):
                    supporting_media_base64 = bool(media.base64)

        results.append(
            CVEDescription(
                cve_id=cve_id,
                source=source,
                lang=str(lang) if lang else "en",
                value=str(value) if value else "",
                supporting_media_type=supporting_media_type,
                supporting_media_base64=supporting_media_base64,
            )
        )

    return results


def _extract_single_cve(cve: CveJsonRecordFormat) -> ExtractedData:
    """Extract structured data from a single CVE record."""
    cve_id = str(cve.root.cveMetadata.cveId.root)

    # Root-level metadata
    data_type = (
        str(cve.root.dataType._value_)
        if hasattr(cve.root.dataType, "_value_")
        else str(cve.root.dataType)
    )
    data_version = (
        str(cve.root.dataVersion.root)
        if hasattr(cve.root.dataVersion, "root")
        else str(cve.root.dataVersion)
    )

    # CVE metadata
    state = cve.root.cveMetadata.state._value_
    assigner_org_id = (
        _get_value(cve.root.cveMetadata.assignerOrgId)
        if cve.root.cveMetadata.assignerOrgId
        else None
    )
    assigner_short_name = (
        cve.root.cveMetadata.assignerShortName.root
        if cve.root.cveMetadata.assignerShortName
        else None
    )

    # Dates
    date_reserved = (
        cve.root.cveMetadata.dateReserved.root
        if cve.root.cveMetadata.dateReserved
        else None
    )
    date_published = (
        cve.root.cveMetadata.datePublished.root
        if cve.root.cveMetadata.datePublished
        else None
    )
    date_updated = (
        cve.root.cveMetadata.dateUpdated.root
        if cve.root.cveMetadata.dateUpdated
        else None
    )
    date_rejected = (
        _get_value(cve.root.cveMetadata.dateRejected)
        if hasattr(cve.root.cveMetadata, "dateRejected")
        and cve.root.cveMetadata.dateRejected
        else None
    )

    # Initialize collections
    descriptions: List[CVEDescription] = []
    metrics: List[CVEMetric] = []
    products: List[CVEProduct] = []
    versions: List[CVEVersion] = []
    cwes: List[CVECWE] = []
    references: List[CVEReference] = []
    credits_list: List[CVECredit] = []
    tags: List[CVETag] = []

    # CNA container fields
    cna_date_public = None
    cna_title = None
    cna_provider_org_id = None
    cna_provider_short_name = None
    cna_provider_date_updated = None
    source_discovery = None
    source_defect = None

    has_cna_metrics = False
    has_adp_metrics = False
    has_affected = False
    has_references = False
    has_credits = False

    # Extract from CNA container
    if isinstance(cve.root.containers.cna, CnaPublishedContainer):
        cna = cve.root.containers.cna
        source = "cna"

        # Title
        if hasattr(cna, "title") and cna.title:
            cna_title = str(cna.title)

        # Date public
        if hasattr(cna, "datePublic") and cna.datePublic:
            cna_date_public = (
                str(cna.datePublic.root)
                if hasattr(cna.datePublic, "root")
                else str(cna.datePublic)
            )

        # Provider metadata
        if hasattr(cna, "providerMetadata") and cna.providerMetadata:
            pm = cna.providerMetadata
            if hasattr(pm, "orgId") and pm.orgId:
                cna_provider_org_id = _get_value(pm.orgId)
            if hasattr(pm, "shortName") and pm.shortName:
                cna_provider_short_name = (
                    str(pm.shortName.root)
                    if hasattr(pm.shortName, "root")
                    else str(pm.shortName)
                )
            if hasattr(pm, "dateUpdated") and pm.dateUpdated:
                cna_provider_date_updated = _get_value(pm.dateUpdated)

        # Source
        if hasattr(cna, "source") and cna.source:
            if hasattr(cna.source, "discovery"):
                source_discovery = _get_value(cna.source.discovery)
            if hasattr(cna.source, "defect") and cna.source.defect:
                defects = [str(d) for d in _get_iterable(cna.source.defect)]
                source_defect = ",".join(defects) if defects else None

        # Descriptions
        if hasattr(cna, "descriptions") and cna.descriptions:
            descriptions.extend(_extract_descriptions(cna.descriptions, cve_id, source))

        # Metrics
        if cna.metrics:
            cna_metrics = _extract_metrics(cna.metrics, cve_id, source)
            metrics.extend(cna_metrics)
            has_cna_metrics = len(cna_metrics) > 0

        # Affected products
        if getattr(cna, "affected", None):
            prods, vers = _extract_products_and_versions(cna.affected, cve_id, source)
            products.extend(prods)
            versions.extend(vers)
            has_affected = len(prods) > 0

        # Problem types (CWEs)
        if hasattr(cna, "problemTypes") and cna.problemTypes:
            cwes.extend(_extract_cwes(cna.problemTypes, cve_id, source))

        # References
        if hasattr(cna, "references") and cna.references:
            refs = _extract_references(cna.references, cve_id, source)
            references.extend(refs)
            has_references = len(refs) > 0

        # Credits
        if hasattr(cna, "credits") and cna.credits:
            creds = _extract_credits(cna.credits, cve_id, source)
            credits_list.extend(creds)
            has_credits = len(creds) > 0

        # X_generator and other extension fields
        if hasattr(cna, "x_generator") and cna.x_generator:
            tags.append(
                CVETag(
                    cve_id=cve_id,
                    source=source,
                    tag_key="x_generator",
                    tag_value=(
                        json.dumps(cna.x_generator)
                        if isinstance(cna.x_generator, dict)
                        else str(cna.x_generator)
                    ),
                )
            )

    # Extract from ADP containers
    if isinstance(cve.root.containers, Containers) and cve.root.containers.adp:
        for adp in cve.root.containers.adp:
            # Build source identifier
            adp_short_name = "unknown"
            if hasattr(adp, "providerMetadata") and adp.providerMetadata:
                if (
                    hasattr(adp.providerMetadata, "shortName")
                    and adp.providerMetadata.shortName
                ):
                    adp_short_name = (
                        str(adp.providerMetadata.shortName.root)
                        if hasattr(adp.providerMetadata.shortName, "root")
                        else str(adp.providerMetadata.shortName)
                    )
            source = f"adp:{adp_short_name}"

            # Title as tag
            if hasattr(adp, "title") and adp.title:
                tags.append(
                    CVETag(
                        cve_id=cve_id,
                        source=source,
                        tag_key="title",
                        tag_value=str(adp.title),
                    )
                )

            # Metrics
            if adp.metrics:
                adp_metrics = _extract_metrics(adp.metrics, cve_id, source)
                metrics.extend(adp_metrics)
                if adp_metrics:
                    has_adp_metrics = True

            # Affected products
            if hasattr(adp, "affected") and adp.affected:
                aff = adp.affected
                if getattr(aff, "root", None):
                    prods, vers = _extract_products_and_versions(aff, cve_id, source)
                    products.extend(prods)
                    versions.extend(vers)

            # Problem types (CWEs)
            if hasattr(adp, "problemTypes") and adp.problemTypes:
                cwes.extend(_extract_cwes(adp.problemTypes, cve_id, source))

            # References
            if hasattr(adp, "references") and adp.references:
                references.extend(_extract_references(adp.references, cve_id, source))

            # Credits
            if hasattr(adp, "credits") and adp.credits:
                credits_list.extend(_extract_credits(adp.credits, cve_id, source))

    # Build CVE record
    cve_record = CVERecord(
        cve_id=cve_id,
        data_type=data_type,
        data_version=data_version,
        state=state,
        assigner_org_id=assigner_org_id,
        assigner_short_name=assigner_short_name,
        date_reserved=date_reserved,
        date_published=date_published,
        date_updated=date_updated,
        date_rejected=date_rejected,
        cna_date_public=cna_date_public,
        cna_title=cna_title,
        cna_provider_org_id=cna_provider_org_id,
        cna_provider_short_name=cna_provider_short_name,
        cna_provider_date_updated=cna_provider_date_updated,
        source_discovery=source_discovery,
        source_defect=source_defect,
        has_cna_metrics=has_cna_metrics,
        has_adp_metrics=has_adp_metrics,
        has_affected=has_affected,
        has_references=has_references,
        has_credits=has_credits,
    )

    return ExtractedData(
        cve=cve_record,
        descriptions=descriptions,
        metrics=metrics,
        products=products,
        versions=versions,
        cwes=cwes,
        references=references,
        credits=credits_list,
        tags=tags,
    )


def _process_file(args: tuple) -> ProcessResult:
    """Process a single CVE file.

    Returns ExtractedData on success, ExtractionError on failure.
    """
    year, file_path = args
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            cve_data = json.load(f)
        cve_model = CveJsonRecordFormat.model_validate(cve_data)
        return _extract_single_cve(cve_model)
    except Exception as e:
        # Extract CVE ID from file path
        cve_id = os.path.basename(file_path).replace(".json", "")
        error_type = type(e).__name__
        # Truncate error message if too long
        error_message = str(e)[:500]
        return ExtractionError(
            cve_id=cve_id,
            file_path=str(file_path),
            error_type=error_type,
            error_message=error_message,
        )


# =============================================================================
# Parquet Schemas
# =============================================================================

CVE_SCHEMA = {
    "cve_id": pl.Utf8,
    "data_type": pl.Utf8,
    "data_version": pl.Utf8,
    "state": pl.Utf8,
    "assigner_org_id": pl.Utf8,
    "assigner_short_name": pl.Utf8,
    "date_reserved": pl.Utf8,
    "date_published": pl.Utf8,
    "date_updated": pl.Utf8,
    "date_rejected": pl.Utf8,
    "cna_date_public": pl.Utf8,
    "cna_title": pl.Utf8,
    "cna_provider_org_id": pl.Utf8,
    "cna_provider_short_name": pl.Utf8,
    "cna_provider_date_updated": pl.Utf8,
    "source_discovery": pl.Utf8,
    "source_defect": pl.Utf8,
    "has_cna_metrics": pl.Boolean,
    "has_adp_metrics": pl.Boolean,
    "has_affected": pl.Boolean,
    "has_references": pl.Boolean,
    "has_credits": pl.Boolean,
}

DESCRIPTION_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "lang": pl.Utf8,
    "value": pl.Utf8,
    "supporting_media_type": pl.Utf8,
    "supporting_media_base64": pl.Boolean,
}

METRIC_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "metric_type": pl.Utf8,
    "format": pl.Utf8,
    "base_score": pl.Float64,
    "exploitability_score": pl.Float64,
    "impact_score": pl.Float64,
    "base_severity": pl.Utf8,
    "vector_string": pl.Utf8,
    "version": pl.Utf8,
    "access_vector": pl.Utf8,
    "access_complexity": pl.Utf8,
    "authentication": pl.Utf8,
    "attack_vector": pl.Utf8,
    "attack_complexity": pl.Utf8,
    "privileges_required": pl.Utf8,
    "user_interaction": pl.Utf8,
    "scope": pl.Utf8,
    "confidentiality_impact": pl.Utf8,
    "integrity_impact": pl.Utf8,
    "availability_impact": pl.Utf8,
    "attack_requirements": pl.Utf8,
    "vulnerable_system_confidentiality": pl.Utf8,
    "vulnerable_system_integrity": pl.Utf8,
    "vulnerable_system_availability": pl.Utf8,
    "subsequent_system_confidentiality": pl.Utf8,
    "subsequent_system_integrity": pl.Utf8,
    "subsequent_system_availability": pl.Utf8,
    "other_type": pl.Utf8,
    "other_content": pl.Utf8,
}

PRODUCT_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "product_id": pl.Utf8,
    "vendor": pl.Utf8,
    "product": pl.Utf8,
    "package_name": pl.Utf8,
    "collection_url": pl.Utf8,
    "repo": pl.Utf8,
    "modules": pl.Utf8,
    "program_files": pl.Utf8,
    "program_routines": pl.Utf8,
    "platforms": pl.Utf8,
    "default_status": pl.Utf8,
    "cpes": pl.Utf8,
    "package_url": pl.Utf8,
}

VERSION_SCHEMA = {
    "cve_id": pl.Utf8,
    "product_id": pl.Utf8,
    "version": pl.Utf8,
    "version_type": pl.Utf8,
    "status": pl.Utf8,
    "less_than": pl.Utf8,
    "less_than_or_equal": pl.Utf8,
    "changes": pl.Utf8,
}

CWE_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "cwe_id": pl.Utf8,
    "cwe_type": pl.Utf8,
    "lang": pl.Utf8,
    "description": pl.Utf8,
}

REFERENCE_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "url": pl.Utf8,
    "name": pl.Utf8,
    "tags": pl.Utf8,
}

CREDIT_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "lang": pl.Utf8,
    "value": pl.Utf8,
    "credit_type": pl.Utf8,
    "user_uuid": pl.Utf8,
}

TAG_SCHEMA = {
    "cve_id": pl.Utf8,
    "source": pl.Utf8,
    "tag_key": pl.Utf8,
    "tag_value": pl.Utf8,
}


# =============================================================================
# Extractor Service
# =============================================================================


class ExtractorService:
    """Service for extracting CVE data from JSON files to Parquet."""

    def __init__(
        self,
        config: Optional[Config] = None,
        quiet: bool = False,
        generate_embeddings: bool = False,
    ):
        """Initialize the extractor service.

        Args:
            config: Configuration instance. Uses default if not provided.
            quiet: If True, suppress progress output.
            generate_embeddings: If True, generate embeddings after extraction.
        """
        self.config = config or get_config()
        self.quiet = quiet
        self.generate_embeddings = generate_embeddings

    def extract_all(
        self, years: Optional[List[int]] = None, output_dir: Optional[Path] = None
    ) -> dict:
        """Extract all CVE data to Parquet files.

        Args:
            years: List of years to process. Uses config default if not provided.
            output_dir: Output directory for Parquet files.

        Returns:
            Dictionary with extraction statistics and paths.
        """
        cve_dir = self.config.cve_dir
        output_dir = output_dir or self.config.data_dir

        # Determine year range
        if years:
            year_set = set(years)
            start_year = min(years)
            end_year = max(years)
        else:
            start_year, end_year = self.config.get_year_range()
            year_set = None

        # Find year directories
        year_dirs = []
        for entry in os.scandir(cve_dir):
            if entry.is_dir():
                try:
                    year = int(entry.name)
                    if year_set:
                        if year in year_set:
                            year_dirs.append((year, entry.path))
                    elif start_year is None or (start_year <= year <= end_year):
                        year_dirs.append((year, entry.path))
                except ValueError:
                    continue

        # Gather all files
        file_args = []
        for year, root in sorted(year_dirs):
            for filename in sorted(os.listdir(root)):
                if filename.endswith(".json"):
                    file_path = os.path.join(root, filename)
                    file_args.append((year, file_path))

        if not self.quiet:
            print(f"Processing {len(file_args)} CVE files...")

        # Process in parallel
        cve_records: List[CVERecord] = []
        descriptions: List[CVEDescription] = []
        metrics: List[CVEMetric] = []
        products: List[CVEProduct] = []
        versions: List[CVEVersion] = []
        cwes: List[CVECWE] = []
        references: List[CVEReference] = []
        credits_list: List[CVECredit] = []
        tags: List[CVETag] = []
        extraction_errors: List[ExtractionError] = []

        with concurrent.futures.ProcessPoolExecutor() as executor:
            if self.quiet:
                results = list(executor.map(_process_file, file_args))
            else:
                progress = Progress(
                    TextColumn("{task.description}"),
                    BarColumn(),
                    TaskProgressColumn(),
                    TimeRemainingColumn(),
                )
                with progress:
                    task = progress.add_task("Extracting", total=len(file_args))
                    results = []
                    for result in executor.map(_process_file, file_args):
                        results.append(result)
                        progress.update(task, advance=1)

        # Aggregate results
        for result in results:
            if isinstance(result, ExtractionError):
                extraction_errors.append(result)
                continue
            cve_records.append(result.cve)
            descriptions.extend(result.descriptions)
            metrics.extend(result.metrics)
            products.extend(result.products)
            versions.extend(result.versions)
            cwes.extend(result.cwes)
            references.extend(result.references)
            credits_list.extend(result.credits)
            tags.extend(result.tags)

        # Report extraction errors
        if extraction_errors and not self.quiet:
            print()
            print(
                f"[yellow]⚠ {len(extraction_errors)} CVEs failed to extract:[/yellow]"
            )

            # Group errors by error type
            errors_by_type: dict[str, List[ExtractionError]] = {}
            for err in extraction_errors:
                key = err.error_type
                if key not in errors_by_type:
                    errors_by_type[key] = []
                errors_by_type[key].append(err)

            for error_type, errors in sorted(
                errors_by_type.items(), key=lambda x: -len(x[1])
            ):
                print(f"  [{len(errors)}] {error_type}:")
                # Show first few examples
                for err in errors[:3]:
                    print(f"      - {err.cve_id}")
                if len(errors) > 3:
                    print(f"      ... and {len(errors) - 3} more")
                # Show one error message as sample
                if errors:
                    sample_msg = errors[0].error_message[:200]
                    if len(errors[0].error_message) > 200:
                        sample_msg += "..."
                    print(f"      Sample error: {sample_msg}")

        # Write to Parquet
        results_paths = {}
        stats = {}

        # CVE records
        cves_path = output_dir / "cves.parquet"
        df_cves = pl.DataFrame([r.model_dump() for r in cve_records], schema=CVE_SCHEMA)
        df_cves.write_parquet(cves_path)
        results_paths["cves"] = cves_path
        stats["cves"] = len(cve_records)

        if not self.quiet:
            print(f"Wrote {len(cve_records)} CVE records to {cves_path}")

        # Descriptions
        if descriptions:
            desc_path = output_dir / "cve_descriptions.parquet"
            df_desc = pl.DataFrame(
                [d.model_dump() for d in descriptions], schema=DESCRIPTION_SCHEMA
            )
            df_desc.write_parquet(desc_path)
            results_paths["descriptions"] = desc_path
            stats["descriptions"] = len(descriptions)

            if not self.quiet:
                print(f"Wrote {len(descriptions)} descriptions to {desc_path}")

        # Metrics
        if metrics:
            metrics_path = output_dir / "cve_metrics.parquet"
            df_metrics = pl.DataFrame(
                [m.model_dump() for m in metrics], schema=METRIC_SCHEMA
            )
            df_metrics.write_parquet(metrics_path)
            results_paths["metrics"] = metrics_path
            stats["metrics"] = len(metrics)

            if not self.quiet:
                print(f"Wrote {len(metrics)} metrics to {metrics_path}")

        # Products
        if products:
            products_path = output_dir / "cve_products.parquet"
            df_products = pl.DataFrame(
                [p.model_dump() for p in products], schema=PRODUCT_SCHEMA
            )
            df_products.write_parquet(products_path)
            results_paths["products"] = products_path
            stats["products"] = len(products)

            if not self.quiet:
                print(f"Wrote {len(products)} products to {products_path}")

        # Versions
        if versions:
            versions_path = output_dir / "cve_versions.parquet"
            df_versions = pl.DataFrame(
                [v.model_dump() for v in versions], schema=VERSION_SCHEMA
            )
            df_versions.write_parquet(versions_path)
            results_paths["versions"] = versions_path
            stats["versions"] = len(versions)

            if not self.quiet:
                print(f"Wrote {len(versions)} versions to {versions_path}")

        # CWEs
        if cwes:
            cwe_path = output_dir / "cve_cwes.parquet"
            df_cwe = pl.DataFrame([c.model_dump() for c in cwes], schema=CWE_SCHEMA)
            df_cwe.write_parquet(cwe_path)
            results_paths["cwes"] = cwe_path
            stats["cwes"] = len(cwes)

            if not self.quiet:
                print(f"Wrote {len(cwes)} CWE mappings to {cwe_path}")

        # References
        if references:
            refs_path = output_dir / "cve_references.parquet"
            df_refs = pl.DataFrame(
                [r.model_dump() for r in references], schema=REFERENCE_SCHEMA
            )
            df_refs.write_parquet(refs_path)
            results_paths["references"] = refs_path
            stats["references"] = len(references)

            if not self.quiet:
                print(f"Wrote {len(references)} references to {refs_path}")

        # Credits
        if credits_list:
            credits_path = output_dir / "cve_credits.parquet"
            df_credits = pl.DataFrame(
                [c.model_dump() for c in credits_list], schema=CREDIT_SCHEMA
            )
            df_credits.write_parquet(credits_path)
            results_paths["credits"] = credits_path
            stats["credits"] = len(credits_list)

            if not self.quiet:
                print(f"Wrote {len(credits_list)} credits to {credits_path}")

        # Tags
        if tags:
            tags_path = output_dir / "cve_tags.parquet"
            df_tags = pl.DataFrame([t.model_dump() for t in tags], schema=TAG_SCHEMA)
            df_tags.write_parquet(tags_path)
            results_paths["tags"] = tags_path
            stats["tags"] = len(tags)

            if not self.quiet:
                print(f"Wrote {len(tags)} tags to {tags_path}")

        # Generate embeddings if requested
        if self.generate_embeddings and descriptions:
            from cvec.services.embeddings import EmbeddingsService

            if not self.quiet:
                print("Generating embeddings for semantic search...")

            embeddings_service = EmbeddingsService(config=self.config, quiet=self.quiet)

            # Use the already-created DataFrames
            embeddings_result = embeddings_service.generate_embeddings(
                df_cves,
                df_desc if descriptions else pl.DataFrame(schema=DESCRIPTION_SCHEMA),
            )

            # Save embeddings
            embeddings_path = output_dir / "cve_embeddings.parquet"
            embeddings_result.write_parquet(embeddings_path)
            results_paths["embeddings"] = embeddings_path
            stats["embeddings"] = len(embeddings_result)

            if not self.quiet:
                print(f"Wrote {len(embeddings_result)} embeddings to {embeddings_path}")

        return {"paths": results_paths, "stats": stats}

    def get_cve(self, cve_id: str) -> Optional[ExtractedData]:
        """Get a single CVE by ID from raw JSON files.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234").

        Returns:
            ExtractedData for the CVE, or None if not found.
        """
        parts = cve_id.split("-")
        if len(parts) < 2:
            return None

        try:
            year = parts[1]
            file_path = self.config.cve_dir / year / f"{cve_id}.json"

            if not file_path.exists():
                return None

            with open(file_path, "r", encoding="utf-8") as f:
                cve_data = json.load(f)

            cve_model = CveJsonRecordFormat.model_validate(cve_data)
            return _extract_single_cve(cve_model)
        except Exception:
            return None
