"""Transparent triage rules, not an asset-aware risk score."""

from dataclasses import dataclass

from vm_analysis.models import CveDetailResponse


@dataclass(frozen=True)
class Assessment:
    label: str
    detail: str
    decision: str
    incomplete: bool


def assess(cve: CveDetailResponse) -> Assessment:
    cvss = cve.cvss.base_score
    epss = cve.epss.score if cve.epss and cve.source_status.epss == "ok" else None
    kev = cve.kev.listed if cve.source_status.kev != "error" else None
    incomplete = cvss is None or epss is None or kev is None

    if kev is True:
        label = "Immediate Action"
        detail = "CISA lists this vulnerability as known exploited. Confirm exposure and prioritize remediation."
        decision = "Apply vendor fixes or mitigations, consider asset criticality, and verify whether compromise occurred."
    elif (cvss is not None and cvss >= 9) or (epss is not None and epss >= 0.7):
        label = "Accelerated Remediation"
        detail = "Available severity or exploitation probability signals justify expedited remediation."
        decision = "Confirm the affected product is deployed and prioritize a short remediation window."
    elif (cvss is not None and cvss >= 7) or (epss is not None and epss >= 0.3):
        label = "Planned Priority"
        detail = "Available source signals indicate a meaningful remediation priority."
        decision = "Schedule remediation through change management and reassess as exploitation information changes."
    elif incomplete:
        label = "Insufficient Data"
        detail = "Missing intelligence prevents a lower-urgency assessment. Unknown values are not zero-risk signals."
        decision = "Review unavailable sources and confirm asset exposure before assigning a remediation priority."
    else:
        label = "Monitor and Triage"
        detail = "Available source signals fall below this tool's expedited remediation thresholds."
        decision = "Confirm exposure and business impact, maintain backlog triage, and monitor for changes."
    return Assessment(label, detail, decision, incomplete)
