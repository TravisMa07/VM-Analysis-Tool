"use client";

import Link from "next/link";

export default function GlobalError({
  error,
  reset
}: {
  error: Error & { digest?: string };
  reset: () => void;
}) {
  return (
    <main className="page-shell">
      <section className="hero">
        <span className="eyebrow">Temporary Error</span>
        <h1>Live vulnerability data could not be loaded.</h1>
        <p>{error.message || "An unexpected error occurred while loading data."}</p>
        <div className="inline-meta">
          <button className="primary-button" type="button" onClick={reset}>
            Retry
          </button>
          <Link className="ghost-button" href="/">
            Back to search
          </Link>
        </div>
      </section>
    </main>
  );
}
