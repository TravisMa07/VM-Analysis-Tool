import Link from "next/link";

export default function NotFound() {
  return (
    <main className="page-shell">
      <section className="hero">
        <span className="eyebrow">Not Found</span>
        <h1>That CVE record could not be loaded.</h1>
        <p>
          The identifier may be invalid, or NVD may not currently have a record
          for it.
        </p>
        <Link className="back-link" href="/">
          Return to search
        </Link>
      </section>
    </main>
  );
}

