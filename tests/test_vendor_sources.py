from vm_analysis.models import CveReference
from vm_analysis.vendor_sources import automated_vendor_guidance


def test_nvd_vendor_references_become_automated_guidance():
    guidance = automated_vendor_guidance("CVE-2024-1086", [CveReference(
        url="https://ubuntu.com/security/CVE-2024-1086", tags=["Vendor Advisory", "Patch"]
    )])
    assert len(guidance) == 1
    assert guidance[0].vendor == "Ubuntu"
    assert guidance[0].automated is True
    assert guidance[0].source_type == "patch"


def test_neutral_intelligence_sources_are_not_vendor_guidance():
    guidance = automated_vendor_guidance("CVE-2024-1086", [CveReference(
        url="https://nvd.nist.gov/vuln/detail/CVE-2024-1086", tags=["Vendor Advisory"]
    )])
    assert guidance == []
