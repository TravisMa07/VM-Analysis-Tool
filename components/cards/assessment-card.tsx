import { CardShell } from "@/components/cards/card-shell";
import { CveDetailResponse } from "@/lib/types";
import { formatPercent } from "@/lib/utils";

type Props = {
  cve: CveDetailResponse;
};

function getAssessment(cve: CveDetailResponse) {
  const cvssScore = cve.cvss.baseScore ?? 0;
  const epssScore = cve.epss?.score ?? 0;
  const inKev = cve.kev.listed;

  if (inKev) {
    return {
      label: "Immediate Action",
      detail:
        "This CVE is listed in KEV, which indicates known active exploitation or strong operational urgency. Treat remediation as an active incident-level priority.",
      decision:
        "Patch or mitigate immediately, verify exposure in your environment, and validate compensating controls if a full fix cannot be deployed today."
    };
  }

  if (cvssScore >= 9 || epssScore >= 0.7) {
    return {
      label: "Accelerated Remediation",
      detail:
        "The technical severity or exploitation probability is high enough to justify expedited remediation, even without KEV listing.",
      decision:
        "Prioritize this in the current remediation cycle, confirm whether the affected product is deployed, and prepare a short response window."
    };
  }

  if (cvssScore >= 7 || epssScore >= 0.3) {
    return {
      label: "Planned Priority",
      detail:
        "The vulnerability has meaningful risk signals but does not currently rise to the highest urgency tier from the available source data.",
      decision:
        "Schedule remediation in normal change management, track vendor guidance, and reassess if EPSS or KEV status changes."
    };
  }

  return {
    label: "Monitor and Triage",
    detail:
      "Current source signals suggest comparatively lower operational urgency, assuming the vulnerable asset is not business critical or externally exposed.",
    decision:
      "Keep this in backlog triage, confirm actual exposure, and revisit when additional exploit or asset context is available."
  };
}

export function AssessmentCard({ cve }: Props) {
  const assessment = getAssessment(cve);

  return (
    <CardShell
      title="Assessment"
      subtitle="Combined operator view across CVE, EPSS, and KEV to support an initial remediation decision."
      fullWidth
    >
      <div className="inline-meta">
        <span className="pill">{assessment.label}</span>
        <span className="pill">
          CVSS {cve.cvss.baseScore !== null && cve.cvss.baseScore !== undefined
            ? cve.cvss.baseScore.toFixed(1)
            : "N/A"}
        </span>
        <span className="pill">EPSS {formatPercent(cve.epss?.score)}</span>
        <span className={`pill${cve.kev.listed ? " warn" : ""}`}>
          KEV {cve.kev.listed ? "Listed" : "Not Listed"}
        </span>
      </div>

      <div className="data-list">
        <div className="data-row">
          <span className="data-label">Key Source Signals</span>
          <span className="data-value">
            CVSS severity is {cve.cvss.baseSeverity ?? "not available"}, EPSS is{" "}
            {formatPercent(cve.epss?.score)}, and KEV is{" "}
            {cve.kev.listed ? "listed" : "not listed"}.
          </span>
        </div>
        <div className="data-row">
          <span className="data-label">Judgment</span>
          <span className="data-value">{assessment.detail}</span>
        </div>
        <div className="data-row">
          <span className="data-label">Decision Guidance</span>
          <span className="data-value">{assessment.decision}</span>
        </div>
      </div>
    </CardShell>
  );
}
