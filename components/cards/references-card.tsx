import { CardShell } from "@/components/cards/card-shell";
import { CveReference } from "@/lib/types";

type Props = {
  references: CveReference[];
};

export function ReferencesCard({ references }: Props) {
  return (
    <CardShell
      title="References"
      subtitle="Canonical source links for the CVE, EPSS, and KEV data shown here."
      fullWidth
    >
      {references.length === 0 ? (
        <p>No references were provided in the NVD record.</p>
      ) : (
        <ul className="reference-list">
          {references.map((reference) => (
            <li className="reference-item" key={reference.url}>
              <a href={reference.url} target="_blank" rel="noreferrer">
                {reference.source ? `${reference.source}: ` : ""}
                {reference.url}
              </a>
            </li>
          ))}
        </ul>
      )}
    </CardShell>
  );
}
