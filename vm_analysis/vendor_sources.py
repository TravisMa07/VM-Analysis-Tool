"""Automatically classify vendor remediation links from NVD references."""

from urllib.parse import urlparse

from vm_analysis.models import CveReference, VendorGuidance

NEUTRAL_DOMAINS = {
    "nvd.nist.gov", "cve.org", "cisa.gov", "first.org", "mitre.org",
}
THIRD_PARTY_DOMAINS = {
    "github.com", "gitlab.com", "exploit-db.com", "packetstormsecurity.com", "vuldb.com",
}
VENDOR_TAGS = {"Vendor Advisory", "Patch", "Release Notes", "Product"}
PATH_HINTS = ("security", "advisory", "bulletin", "patch", "update", "release", "download")


def candidate_vendor_reference(reference: CveReference) -> bool:
    parsed = urlparse(reference.url)
    host = (parsed.hostname or "").lower().removeprefix("www.")
    if (parsed.scheme != "https" or not host or host in NEUTRAL_DOMAINS
            or host.endswith(".nist.gov") or host in THIRD_PARTY_DOMAINS):
        return False
    tagged = bool(set(reference.tags) & VENDOR_TAGS)
    hinted = any(token in (parsed.path + "?" + (parsed.query or "")).lower() for token in PATH_HINTS)
    return tagged or hinted


def vendor_name(hostname: str) -> str:
    host = hostname.removeprefix("www.")
    parts = host.split(".")
    return parts[-2].replace("-", " ").title() if len(parts) >= 2 else host


def source_type(tags: list[str], url: str) -> str:
    lowered = {tag.lower() for tag in tags}
    if "patch" in lowered:
        return "patch"
    if "release notes" in lowered:
        return "release_notes"
    if "support" in lowered:
        return "support"
    return "vendor_advisory"


def automated_vendor_guidance(cve_id: str, references: list[CveReference]) -> list[VendorGuidance]:
    results = []
    seen = set()
    for reference in references:
        parsed = urlparse(reference.url)
        host = (parsed.hostname or "").lower().removeprefix("www.")
        if not host or host in NEUTRAL_DOMAINS or host.endswith(".nist.gov"):
            continue
        tagged = bool(set(reference.tags) & VENDOR_TAGS)
        hinted = any(token in (parsed.path + "?" + (parsed.query or "")).lower() for token in PATH_HINTS)
        if not tagged and not hinted:
            continue
        if reference.url in seen:
            continue
        seen.add(reference.url)
        kind = source_type(reference.tags, reference.url)
        results.append(VendorGuidance(
            cve_id=cve_id,
            vendor=vendor_name(host),
            product="Affected product from the vendor advisory",
            platform="Vendor-supported platform",
            advisory_url=reference.url,
            remediation="Open the official vendor source, confirm the affected release, and apply the fixed package, update, or release identified there.",
            mitigation="Use the vendor's documented workaround or mitigation if the fixed update cannot be applied immediately.",
            verified_on="NVD reference",
            confidence="needs_review",
            applicability="needs_asset_context",
            source_type=kind,
            automated=True,
        ))
    return results
