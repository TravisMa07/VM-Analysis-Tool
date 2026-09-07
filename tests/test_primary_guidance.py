from vm_analysis.models import CveReference, VendorGuidance
from vm_analysis.service import select_primary_guidance, vendor_reference_list


def guidance(**updates):
    values = {
        "cve_id": "CVE-2024-1086", "vendor": "Vendor", "product": "Kernel",
        "platform": "Linux", "advisory_url": "https://vendor.example/advisory",
        "remediation": "Apply the vendor update.", "verified_on": "2026-09-07",
    }
    values.update(updates)
    return VendorGuidance(**values)


def test_fixed_version_vendor_advisory_beats_upstream_patch():
    patch = guidance(source_type="patch", advisory_status="extracted", advisory_url="https://kernel.org/patch")
    vendor = guidance(source_type="vendor_advisory", advisory_status="extracted",
                      fixed_version="6.5.0-41", advisory_url="https://ubuntu.com/security/CVE-2024-1086")
    assert select_primary_guidance([patch, vendor]).advisory_url == vendor.advisory_url


def test_partial_source_is_selected_when_no_usable_extracted_source_exists():
    partial = guidance(advisory_status="partial")
    error = guidance(advisory_status="error", advisory_url="https://vendor.example/error")
    assert select_primary_guidance([error, partial]).advisory_url == partial.advisory_url


def test_vendor_references_are_deduplicated_and_mark_primary():
    primary = guidance(fixed_version="6.5.0-41", advisory_url="https://ubuntu.com/security/CVE-2024-1086")
    refs = vendor_reference_list([primary, primary], [
        CveReference(url=primary.advisory_url, source="Vendor Advisory"),
        CveReference(url="https://nvd.nist.gov/vuln/detail/CVE-2024-1086", source="CVE / NVD"),
    ], primary)
    assert len(refs) == 2
    assert sum(reference.primary for reference in refs) == 1
