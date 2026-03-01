import { CardShell } from "@/components/cards/card-shell";
import { CvssData } from "@/lib/types";

type Props = {
  cvss: CvssData;
};

export function CvssCard({ cvss }: Props) {
  return (
    <CardShell
      title="CVSS"
      subtitle="Base scoring from the preferred metric available in NVD."
    >
      <div className="inline-meta">
        <span className="pill">
          {cvss.baseScore !== null && cvss.baseScore !== undefined
            ? `Base ${cvss.baseScore.toFixed(1)}`
            : "Base N/A"}
        </span>
        <span className="pill">{cvss.baseSeverity ?? "Severity unavailable"}</span>
        <span className="pill">v{cvss.version ?? "N/A"}</span>
      </div>

      <div className="data-list">
        <div className="data-row">
          <span className="data-label">Vector</span>
          <span className="data-value">{cvss.vector ?? "Not available"}</span>
        </div>
        <div className="data-row">
          <span className="data-label">Exploitability Score</span>
          <span className="data-value">
            {cvss.exploitabilityScore ?? "Not available"}
          </span>
        </div>
        <div className="data-row">
          <span className="data-label">Impact Score</span>
          <span className="data-value">{cvss.impactScore ?? "Not available"}</span>
        </div>
      </div>
    </CardShell>
  );
}

