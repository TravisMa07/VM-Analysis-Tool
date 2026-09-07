import asyncio

import pytest

from vm_analysis.assessment import assess
from vm_analysis.demo import DEMO_ANALYSES
from vm_analysis.models import EpssData, KevData, SourceStatus
from vm_analysis.service import get_cve_analysis


@pytest.mark.parametrize("cvss,epss,listed,label", [
    (1, 0.01, True, "Immediate Action"),
    (9, 0.01, False, "Accelerated Remediation"),
    (1, 0.7, False, "Accelerated Remediation"),
    (7, 0.01, False, "Planned Priority"),
    (1, 0.3, False, "Planned Priority"),
    (6.9, 0.29, False, "Monitor and Triage"),
    (0, 0, False, "Monitor and Triage"),
    (None, None, None, "Insufficient Data"),
    (1, None, False, "Insufficient Data"),
    (1, 0.01, None, "Insufficient Data"),
    (None, 0.01, False, "Insufficient Data"),
    (9, None, None, "Accelerated Remediation"),
    (None, None, True, "Immediate Action"),
])
def test_priority_rules(cvss, epss, listed, label):
    cve = DEMO_ANALYSES["CVE-2024-3400"].model_copy(deep=True)
    cve.cvss.base_score = cvss
    cve.epss = EpssData(cve_id=cve.cve_id, score=epss) if epss is not None else None
    cve.kev = KevData(listed=listed)
    cve.source_status = SourceStatus(nvd="ok", epss="ok" if epss is not None else "error",
                                    kev="error" if listed is None else "ok" if listed else "not_listed")
    result = assess(cve)
    assert result.label == label
    assert result.incomplete == (cvss is None or epss is None or listed is None)


async def test_enrichments_run_concurrently(monkeypatch):
    """Both enrichments must start before either can finish (no timing assertion)."""
    started_epss, started_kev = asyncio.Event(), asyncio.Event()
    example = DEMO_ANALYSES["CVE-2024-3400"]
    async def nvd(*args):
        from vm_analysis.models import NvdDetail
        return NvdDetail.model_validate(example.model_dump())
    async def epss(*args):
        started_epss.set()
        await started_kev.wait()
        return example.epss
    async def kev(*args):
        started_kev.set()
        await started_epss.wait()
        return example.kev
    monkeypatch.setattr("vm_analysis.service.get_nvd_cve", nvd)
    monkeypatch.setattr("vm_analysis.service.get_epss", epss)
    monkeypatch.setattr("vm_analysis.service.get_kev", kev)
    result = await asyncio.wait_for(get_cve_analysis(None, example.cve_id), timeout=1)
    assert result.source_status.epss == result.source_status.kev == "ok"
