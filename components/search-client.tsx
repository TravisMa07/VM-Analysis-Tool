"use client";

import Link from "next/link";
import { FormEvent, useState } from "react";
import { SearchResponse } from "@/lib/types";
import { formatDate } from "@/lib/utils";

export function SearchClient() {
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const trimmedQuery = query.trim();

    if (!trimmedQuery) {
      setError("Enter a CVE ID or a keyword to search.");
      setResults(null);
      return;
    }

    setLoading(true);
    setError(null);

    try {
      const response = await fetch(
        `/api/search?q=${encodeURIComponent(trimmedQuery)}`,
        {
          method: "GET",
          headers: {
            Accept: "application/json"
          }
        }
      );

      if (!response.ok) {
        const body = (await response.json().catch(() => null)) as
          | { error?: string }
          | null;

        throw new Error(body?.error ?? "Search failed.");
      }

      const payload = (await response.json()) as SearchResponse;
      setResults(payload);
    } catch (caughtError) {
      const message =
        caughtError instanceof Error ? caughtError.message : "Search failed.";
      setError(message);
      setResults(null);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section className="search-panel">
      <form className="search-form" onSubmit={handleSubmit}>
        <div className="search-form-row">
          <input
            className="search-input"
            type="search"
            name="query"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Try CVE-2024-3400 or search by vendor, product, or keyword"
            aria-label="Search CVEs"
          />
          <button className="primary-button" type="submit" disabled={loading}>
            {loading ? "Searching..." : "Search"}
          </button>
        </div>
        <p className="helper-text">
          Search NVD live, then open a one-page CVE analysis with CVSS, EPSS,
          and KEV context.
        </p>
        {error ? <p className="error-text">{error}</p> : null}
      </form>

      {results ? (
        <div className="results-list" aria-live="polite">
          <p className="status-text">
            {results.totalResults} result{results.totalResults === 1 ? "" : "s"}{" "}
            from {results.mode === "cveId" ? "exact CVE lookup" : "keyword search"}
          </p>

          {results.results.length === 0 ? (
            <div className="result-card">
              <h2>No matching CVEs</h2>
              <p>Try a broader keyword or a different CVE identifier.</p>
            </div>
          ) : (
            results.results.map((item) => (
              <Link
                className="result-card result-card-link"
                href={`/cve/${item.cveId}`}
                key={item.cveId}
              >
                <span className="eyebrow">{item.cveId}</span>
                <h2>{item.title}</h2>
                <p>{item.summary}</p>
                <div className="result-meta">
                  <span className="pill">
                    CVSS{" "}
                    {item.cvssBaseScore !== null && item.cvssBaseScore !== undefined
                      ? item.cvssBaseScore.toFixed(1)
                      : "N/A"}
                  </span>
                  <span className="pill">
                    {item.cvssSeverity ?? "Severity unavailable"}
                  </span>
                  <span className="pill">Published {formatDate(item.published)}</span>
                </div>
                <span className="result-link">Select CVE</span>
              </Link>
            ))
          )}
        </div>
      ) : null}
    </section>
  );
}
