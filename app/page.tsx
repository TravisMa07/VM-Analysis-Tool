import { SearchClient } from "@/components/search-client";

export const dynamic = "force-dynamic";

export default function HomePage() {
  return (
    <main className="page-shell">
      <section className="hero">
        <span className="eyebrow">Live Vulnerability Context</span>
        <h1>Query CVEs and prioritize faster.</h1>
        <p>
          This tool aggregates NVD CVE and CVSS data, FIRST EPSS enrichment,
          and CISA KEV intelligence into a single modular analysis view so
          triage decisions can happen faster.
        </p>
        <SearchClient />
      </section>
    </main>
  );
}

