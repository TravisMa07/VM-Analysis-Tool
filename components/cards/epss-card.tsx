import { CardShell } from "@/components/cards/card-shell";
import { EpssData } from "@/lib/types";
import { formatDate, formatPercent } from "@/lib/utils";

type Props = {
  epss: EpssData | null;
  status: "ok" | "not_found" | "error";
};

export function EpssCard({ epss, status }: Props) {
  return (
    <CardShell
      title="EPSS"
      subtitle="FIRST exploitation probability enrichment."
    >
      <div className="inline-meta">
        <span className={`pill${status === "error" ? " danger" : ""}`}>
          {status === "ok"
            ? "Available"
            : status === "not_found"
              ? "No EPSS record"
              : "EPSS unavailable"}
        </span>
      </div>

      <div className="data-list">
        <div className="data-row">
          <span className="data-label">EPSS Score</span>
          <span className="data-value">{formatPercent(epss?.score)}</span>
        </div>
        <div className="data-row">
          <span className="data-label">Percentile</span>
          <span className="data-value">{formatPercent(epss?.percentile)}</span>
        </div>
        <div className="data-row">
          <span className="data-label">Score Date</span>
          <span className="data-value">{formatDate(epss?.date)}</span>
        </div>
      </div>
    </CardShell>
  );
}

