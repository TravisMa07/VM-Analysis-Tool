import { CardShell } from "@/components/cards/card-shell";
import { KevData } from "@/lib/types";
import { formatDate } from "@/lib/utils";

type Props = {
  kev: KevData;
  status: "ok" | "not_listed" | "error";
};

export function KevCard({ kev, status }: Props) {
  return (
    <CardShell
      title="KEV"
      subtitle="CISA known exploited vulnerability catalog status."
    >
      <div className="inline-meta">
        <span
          className={`pill${
            status === "error"
              ? " danger"
              : status === "ok"
                ? " warn"
                : ""
          }`}
        >
          {status === "ok"
            ? "Listed in KEV"
            : status === "not_listed"
              ? "Not listed"
              : "KEV unavailable"}
        </span>
      </div>

      <div className="data-list">
        <div className="data-row">
          <span className="data-label">Vendor</span>
          <span className="data-value">{kev.vendorProject ?? "Not available"}</span>
        </div>
        <div className="data-row">
          <span className="data-label">Product</span>
          <span className="data-value">{kev.product ?? "Not available"}</span>
        </div>
        <div className="data-row">
          <span className="data-label">Vulnerability Name</span>
          <span className="data-value">
            {kev.vulnerabilityName ?? "Not available"}
          </span>
        </div>
        <div className="data-row">
          <span className="data-label">Date Added</span>
          <span className="data-value">{formatDate(kev.dateAdded)}</span>
        </div>
        <div className="data-row">
          <span className="data-label">Due Date</span>
          <span className="data-value">{formatDate(kev.dueDate)}</span>
        </div>
        <div className="data-row">
          <span className="data-label">Required Action</span>
          <span className="data-value">
            {kev.requiredAction ?? "Not available"}
          </span>
        </div>
        <div className="data-row">
          <span className="data-label">Notes</span>
          <span className="data-value">{kev.notes ?? "Not available"}</span>
        </div>
      </div>
    </CardShell>
  );
}

