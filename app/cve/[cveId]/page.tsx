import Link from "next/link";
import { notFound } from "next/navigation";
import { AssessmentCard } from "@/components/cards/assessment-card";
import { CveOverviewCard } from "@/components/cards/cve-overview-card";
import { CvssCard } from "@/components/cards/cvss-card";
import { EpssCard } from "@/components/cards/epss-card";
import { KevCard } from "@/components/cards/kev-card";
import { ReferencesCard } from "@/components/cards/references-card";
import { getDemoCveAnalysis } from "@/lib/mock-data";
import { getCveAnalysis } from "@/lib/services/cve-analysis";
import { isValidCveId, normalizeCveId } from "@/lib/utils";

export const dynamic = "force-dynamic";

type Props = {
  params:
    | {
        cveId: string;
      }
    | Promise<{
        cveId: string;
      }>;
  searchParams?:
    | {
        demo?: string;
      }
    | Promise<{
        demo?: string;
      }>;
};

export default async function CveDetailPage({ params, searchParams }: Props) {
  const resolvedParams = await Promise.resolve(params);
  const resolvedSearchParams = await Promise.resolve(searchParams);
  const cveId = normalizeCveId(resolvedParams.cveId);
  const useDemoData = resolvedSearchParams?.demo === "1";

  if (!isValidCveId(cveId)) {
    notFound();
  }

  const cve = useDemoData
    ? getDemoCveAnalysis(cveId)
    : await getCveAnalysis(cveId);

  if (!cve) {
    notFound();
  }

  return (
    <main className="page-shell">
      <Link className="back-link" href="/">
        Back to search
      </Link>

      <section className="detail-header">
        <span className="eyebrow">{cve.cveId}</span>
        <h1>One-page vulnerability analysis.</h1>
        <p>
          {useDemoData ? "Demo data loaded." : "Live source status:"} NVD{" "}
          {cve.sourceStatus.nvd}, EPSS {cve.sourceStatus.epss}, KEV{" "}
          {cve.sourceStatus.kev}.
        </p>
      </section>

      <section className="detail-grid">
        <AssessmentCard cve={cve} />
        <CveOverviewCard cve={cve} />
        <CvssCard cvss={cve.cvss} />
        <EpssCard epss={cve.epss} status={cve.sourceStatus.epss} />
        <KevCard kev={cve.kev} status={cve.sourceStatus.kev} />
        <ReferencesCard references={cve.references} />
      </section>
    </main>
  );
}
