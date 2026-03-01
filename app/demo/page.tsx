import Link from "next/link";
import { DEMO_SEARCH_RESPONSE } from "@/lib/mock-data";
import { formatDate } from "@/lib/utils";

export default function DemoPage() {
  return (
    <main className="page-shell">
      <section className="hero">
        <span className="eyebrow">Local Demo</span>
        <h1>Test the UI without live API calls.</h1>
        <p>
          This page renders a built-in dataset so you can validate the search
          and analysis layout locally before wiring production credentials or
          relying on upstream availability.
        </p>

        <div className="results-list">
          <p className="status-text">
            {DEMO_SEARCH_RESPONSE.totalResults} demo results ready for local
            testing
          </p>

          {DEMO_SEARCH_RESPONSE.results.map((item) => (
            <Link
              className="result-card result-card-link"
              href={`/cve/${item.cveId}?demo=1`}
              key={item.cveId}
            >
              <span className="eyebrow">{item.cveId}</span>
              <h2>{item.title}</h2>
              <p>{item.summary}</p>
              <div className="result-meta">
                <span className="pill">CVSS {item.cvssBaseScore?.toFixed(1)}</span>
                <span className="pill">{item.cvssSeverity}</span>
                <span className="pill">Published {formatDate(item.published)}</span>
              </div>
              <span className="result-link">Select CVE</span>
            </Link>
          ))}
        </div>

        <Link className="back-link" href="/">
          Return to live search
        </Link>
      </section>
    </main>
  );
}
