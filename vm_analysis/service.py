"""NVD is required; EPSS and KEV enrichments may fail independently."""

import asyncio
import logging

import httpx

from vm_analysis.adapters.epss import get_epss
from vm_analysis.adapters.kev import get_kev
from vm_analysis.adapters.nvd import get_nvd_cve
from vm_analysis.models import (AssetContext, CveDetailResponse, CveReference, KevData, SourceFreshness,
                                SourceStatus, VendorGuidance, VendorReference)
from vm_analysis.utils import normalize_cve_id
from vm_analysis.advisory_scraper import enrich_vendor_guidance

logger = logging.getLogger(__name__)


def guidance_rank(item: VendorGuidance) -> tuple[int, int, int]:
    status_rank = {"extracted": 0, "partial": 1, "discovered": 2, "stale": 3, "error": 4}.get(item.advisory_status, 5)
    facts = int(bool(item.fixed_version or item.update_identifiers)) * 3
    facts += int(bool(item.affected_versions and item.remediation)) * 2
    source_rank = {"vendor_advisory": 0, "support": 1, "release_notes": 2, "patch": 3}.get(item.source_type, 4)
    return status_rank, -(facts), source_rank


def select_primary_guidance(guidance: list[VendorGuidance]) -> VendorGuidance | None:
    if not guidance:
        return None
    return min(guidance, key=guidance_rank)


def vendor_reference_list(guidance: list[VendorGuidance], references: list[CveReference],
                          primary: VendorGuidance | None) -> list[VendorReference]:
    result, seen = [], set()
    primary_url = primary.advisory_url if primary else None
    for item in guidance:
        if item.advisory_url in seen:
            continue
        seen.add(item.advisory_url)
        result.append(VendorReference(vendor=item.vendor, url=item.advisory_url,
                                      source_type=item.source_type, advisory_status=item.advisory_status,
                                      primary=item.advisory_url == primary_url))
    for reference in references:
        if reference.url in seen:
            continue
        seen.add(reference.url)
        result.append(VendorReference(vendor=reference.source or "Reference", url=reference.url,
                                      source_type="general", advisory_status="not_available"))
    return result


def source_references(cve_id: str) -> list[CveReference]:
    return [
        CveReference(url=f"https://nvd.nist.gov/vuln/detail/{cve_id}", source="CVE / NVD"),
        CveReference(url=f"https://api.first.org/data/v1/epss?cve={cve_id}", source="EPSS / FIRST"),
        CveReference(url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog", source="KEV / CISA"),
    ]


async def get_cve_analysis(client: httpx.AsyncClient, cve_id: str,
                           asset_context: AssetContext | None = None) -> CveDetailResponse | None:
    cve_id = normalize_cve_id(cve_id)
    nvd = await get_nvd_cve(client, cve_id)
    if nvd is None:
        return None
    epss_result, kev_result, vendor_result = await asyncio.gather(
        get_epss(client, cve_id), get_kev(client, cve_id),
        enrich_vendor_guidance(client, cve_id, nvd.references), return_exceptions=True,
    )
    epss_failed = isinstance(epss_result, Exception)
    kev_failed = isinstance(kev_result, Exception)
    vendor_failed = isinstance(vendor_result, Exception)
    for source, failed in (("EPSS", epss_failed), ("KEV", kev_failed), ("vendor advisory", vendor_failed)):
        if failed:
            logger.warning("%s enrichment unavailable for %s", source, cve_id)
    epss = None if epss_failed else epss_result
    kev = KevData() if kev_failed else kev_result
    guidance, advisory_status = ([], "error") if vendor_failed else vendor_result
    if asset_context:
        guidance = [item.model_copy(update={"applicability": "potentially_applicable"}) for item in guidance]
    data = nvd.model_dump(exclude={"references"})
    primary = select_primary_guidance(guidance)
    references = merge_references(nvd.references, source_references(cve_id))
    return CveDetailResponse(
        **data, references=references, epss=epss, kev=kev,
        source_status=SourceStatus(
            nvd="ok", epss="error" if epss_failed else "ok" if epss else "not_found",
            kev="error" if kev_failed else "ok" if kev.listed else "not_listed",
        ),
        vendor_guidance=guidance,
        vendor_guidance_status="matched" if guidance else "not_available",
        advisory_status=advisory_status,
        primary_vendor_guidance=primary,
        vendor_references=vendor_reference_list(guidance, references, primary),
        source_freshness=SourceFreshness(
            nvd_last_modified=nvd.last_modified,
            epss_date=epss.date if epss else None,
            kev_date_added=kev.date_added if kev else None,
            vendor_verified_on=None,
        ),
        asset_context=asset_context,
    )


def merge_references(*groups: list[CveReference]) -> list[CveReference]:
    result, seen = [], set()
    for group in groups:
        for reference in group:
            if reference.url not in seen:
                result.append(reference)
                seen.add(reference.url)
    return result
