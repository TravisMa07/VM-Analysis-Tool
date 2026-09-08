# VM Analysis Tool

A Python/FastAPI application for searching vulnerabilities and reviewing NVD CVE/CVSS data, FIRST EPSS scores, CISA KEV status, and automatically discovered vendor remediation guidance together.

The application uses server-rendered HTML and CSS. React, Next.js, TypeScript, and a Node build are no longer required. Small optional JavaScript files provide autocomplete, incremental results, and copy actions; the search form works without JavaScript.

## Run locally

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/). Dependencies are recorded in `pyproject.toml` and pinned in `uv.lock`.

```sh
uv sync --locked
uv run uvicorn main:app --reload
```

Open:

- [Live search](http://127.0.0.1:8000/)
- [Offline demo](http://127.0.0.1:8000/demo)
- [Interactive API documentation](http://127.0.0.1:8000/docs)
- [OpenAPI schema](http://127.0.0.1:8000/openapi.json)

Alternatively, without uv:

```sh
python -m venv .venv
# Windows PowerShell:
.venv\Scripts\Activate.ps1
# macOS/Linux: source .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn main:app --reload
```

Copy `.env.example` to `.env` to customize the optional settings. The app loads this file automatically; existing environment variables take precedence.

| Variable | Default | Purpose |
| --- | --- | --- |
| `NVD_API_KEY` | Empty | Optional NVD API key; sent only to NVD from the server |
| `REQUEST_TIMEOUT_MS` | `8000` | Positive integer; maximum time for each upstream HTTP request |

## How it works

```text
Browser or API client
        |
        v
FastAPI routes (main.py)
        |
        +-- Search --> NVD adapter --> normalized search results
        |
        +-- Detail --> analysis service
                           |
                           +-- NVD metadata (required)
                           +-- EPSS + KEV (concurrent, optional enrichments)
                           +-- Vendor remediation references (derived from NVD)
                           |
                           v
                  Pydantic response model
                           |
                           +-- JSON response for API clients
                           +-- assessment rules + Jinja HTML for the browser
```

- `vm_analysis/adapters/` contains one integration per source. Adapters translate external JSON into the application's data models.
- `vm_analysis/service.py` combines data and records each source's status. It skips enrichment when NVD has no record.
- `vm_analysis/vendor_sources.py` classifies vendor advisories, patches, release notes, and support links from NVD references into remediation guidance.
- `vm_analysis/advisory_scraper.py` fetches candidate advisories with bounded caching and extracts versions, packages, update IDs, mitigations, reboot requirements, exploitation language, and display-only vendor commands.
- `vm_analysis/assessment.py` contains independently testable prioritization rules. Templates only present their results.
- `vm_analysis/models.py` defines response data with Pydantic. Python uses snake_case; public JSON uses camelCase for compatibility.
- `templates/` contains HTML pages; `static/` holds the existing responsive styling and optional autocomplete and search feedback.
- `vm_analysis/data/` contains frozen illustrative demo fixtures. Demo pages do not fetch upstream data; their scores/catalog status are not current intelligence.

Vendor guidance is automatically derived from the NVD reference list and is labelled potentially applicable unless an analyst supplies optional OS/product/version context. It does not prove that an asset is vulnerable. NVD references tagged as vendor advisories, patches, release notes, or support links are promoted into the remediation section; neutral sources such as NVD, CISA, FIRST, and MITRE are excluded.

Each request owns an HTTPX async client. EPSS and KEV requests overlap using `asyncio.gather`, so one enrichment does not wait for the other. The client closes after the request. There is no database, login, background worker, or persistent cache. Autocomplete has a bounded process-local cache.

## API

| Route | Behavior |
| --- | --- |
| `GET /api/search?q=<query>&limit=10&startIndex=0` | Exact CVE lookup or paginated keyword search; per-page limit clamped to 1-25 |
| `GET /api/cve/<CVE-ID>` | NVD metadata enriched with EPSS and KEV |

CVE identifiers are trimmed and normalized to uppercase. Empty search queries and invalid API CVE IDs return `400`. Missing NVD detail records return `404`; no search matches return `200` with an empty results list. NVD failures return `502`. Errors retain the `{"error": "message"}` shape.

EPSS or KEV failure does not discard a valid NVD record: the response is `200`, with the failing source marked `error` in `sourceStatus`. Optional `os`, `product`, and `version` query parameters on the CVE endpoint mark automatically discovered guidance as potentially applicable without changing the global CVE assessment.

**Intentional compatibility change:** `kev.listed` is now nullable. `true` means listed, `false` means a successful catalog lookup found no match, and `null` means the catalog could not be checked. Consumers must not treat `null` as a confirmed negative. Missing optional fields are serialized as JSON `null`.

```sh
curl "http://127.0.0.1:8000/api/search?q=openssl&limit=5"
curl "http://127.0.0.1:8000/api/cve/CVE-2024-3400"
```

The browser search now submits a standard GET form to `/?q=...`. Detail URLs remain `/cve/<CVE-ID>`, and `/demo` links to detail pages with `?demo=1`.

## Assessment rules and limitations

Rules are evaluated in this order:

1. Confirmed KEV listing: **Immediate Action**.
2. CVSS >= 9 or EPSS >= 0.70: **Accelerated Remediation**.
3. CVSS >= 7 or EPSS >= 0.30: **Planned Priority**.
4. Missing CVSS, EPSS score, or KEV status: **Insufficient Data**.
5. Otherwise: **Monitor and Triage**.

Known high-priority signals still justify action when another source is missing, with an explicit incomplete-intelligence notice. Missing scores are never converted to zero. These thresholds are project heuristics, not a validated risk model or an organizational SLA. Asset exposure, business criticality, and compensating controls still require analyst judgment. A KEV listing does not prove that your own assets are compromised.

The NVD metric preference remains CVSS 3.1, then 3.0, then 2.0. CVSS 4.0 support and asset-aware prioritization are future work. Each live analysis downloads the KEV catalog; public source latency and rate limits affect availability.

## Tests

```sh
uv run pytest -q
```

Tests use HTTPX mock transports, so they require no credentials or upstream connectivity. Coverage includes adapter normalization, exact/keyword lookup, limits, timeouts, malformed responses, partial enrichment failures, concurrent requests, assessment boundaries, JSON field names, HTML escaping, demo pages, and API documentation.

After changing dependencies, update `uv.lock` with `uv lock`, then regenerate the pip-compatible runtime file:

```sh
uv export --locked --no-dev --no-emit-project --no-hashes --format requirements-txt --output-file requirements.txt
```

## Explaining the project in an interview

"I built a vulnerability triage tool that normalizes three intelligence sources into one view. NVD provides the vulnerability record and technical severity; EPSS and KEV add exploitation context. Source adapters isolate API differences, and a service combines their results. Optional sources can fail independently without hiding the core record. FastAPI exposes documented JSON endpoints and renders HTML for analysts. Prioritization rules are explicit, tested, and distinguish missing intelligence from low scores."

Be prepared to explain:

- **Why FastAPI?** Python routes, response validation, generated API documentation, and async HTTP integration in one application.
- **Why separate adapters?** Upstream response changes can be addressed without rewriting the UI or assessment rules.
- **Why concurrency?** EPSS and KEV are independent network requests; overlapping their wait time reduces enrichment latency.
- **Why Pydantic?** It validates the normalized model and documents the API contract; it does not guarantee the source data is factually correct.
- **Why tolerate partial failure?** Analysts can still use available intelligence while seeing exactly which source could not be checked.
- **What would you improve next?** Cache KEV with freshness information, handle upstream rate limits, and add asset context before claiming organization-specific risk.

## Deployment

For a Python host, install `requirements.txt` and start `uvicorn main:app --host 0.0.0.0 --port <host-port>`. Run without `--reload` in production. Include `templates/`, `static/`, and `vm_analysis/data/` in the deployment.

For the existing Vercel project, switch its framework preset from Next.js to FastAPI and clear old npm build/install and `.next` output overrides. The root `main.py` exports `app`, and the project includes Python dependency files. Check the home page, demo, CSS, docs, and a live lookup on a preview deployment before promoting it. See [Vercel's FastAPI documentation](https://vercel.com/docs/frameworks/backend/fastapi).

This migration does not itself update the hosted deployment or its dashboard settings. The prior deployment URL is [vm-analysis-tool.vercel.app](https://vm-analysis-tool.vercel.app/).

The root `index.html` remains a separate legacy static demo. It contains its own demo data and JavaScript, does not run the Python service, and is not served as the FastAPI home page. Use `/demo` to review the migrated application.

## Search autocomplete

The live search box suggests common vendors, products, and topics after two characters, plus up to four NVD CVEs after three characters and a 500 ms typing pause. Up to eight matches appear, followed by a separate “Search for…” action. Use arrow keys and Enter to select; Escape dismisses the list. Selecting a term submits its keyword search; selecting a CVE opens its analysis. The form still works without JavaScript.

Edit `static/suggestion-catalog.json` to maintain common terms: each entry has a `label`, `category`, `query`, and `aliases`. Matching ignores case, spaces, and punctuation and ranks exact matches, prefixes, word prefixes, then one-edit typos in names of at least five letters. Aliases such as RCE are supported; this is autocomplete, not semantic retrieval or a complete vendor/product catalog.

`GET /api/suggestions?q=<query>` returns an array of at most four existing search-result objects (camelCase fields). Queries under three characters return `[]`; queries over 200 characters return `400`. Known indexed names and identifiers return verified catalog suggestions without upstream calls. Other complete CVE IDs use exact NVD lookup. Numeric fragments (such as `46300`) match the final CVE number, including across years, using indexed and cached records; no year is guessed and no fuzzy correction is applied to numbers. Incomplete CVE IDs also match indexed and cached records, so prefix coverage is limited. No demo records or enrichment data are used as live suggestions.

Suggestions use a process-local cache (five minutes, at most 256 queries), share identical in-flight requests, and pause new upstream suggestion lookups for 15 seconds after a failure. Failures return `502` with the standard error shape; cached and local suggestions remain usable. The cache resets on restart and is independent across workers/serverless instances. NVD availability and rate limits still apply; no database or background synchronization is added.

Run the Python suite with `uv run pytest -q`; run catalog ranking tests with `node --test tests/search.test.cjs` (Node is optional for these developer tests only).

### Automated vendor remediation

The live analysis does not require a pre-seeded CVE catalog. NVD supplies the reference URLs and tags; the application classifies likely vendor remediation links and presents them with an automated action summary. Since NVD references do not consistently contain fixed package versions or complete remediation steps, the user must open the official source to confirm the applicable release and update.

The detail page separates global priority from applicability, shows vendor guidance independently from NVD/EPSS/KEV references, provides optional analyst context filters, and renders an evidence-ready summary for handoff. Asset context is not persisted and no external CMDB is required.

### Named vulnerability index

`static/vulnerability-index.json` is the editable, version-controlled name index, loaded by both the browser and Python service. Each record includes `cveId`, `label`, `aliases`, `relatedTerms`, `summary`, advisory `sources`, and `verifiedOn`. Add entries using verified advisory mappings and review them as source information changes; the server loads the file at startup, so restart after editing it. This release seeds Fragnesia and the two Dirty Frag CVEs. It is not a complete or automatically synchronized CVE database.

Examples: `46300`, `fragn`, `fragnesia`, and `fragnesa` suggest CVE-2026-46300. `dirty frag`, `dirtyfrag`, and `dirty-frag` suggest CVE-2026-43284 and CVE-2026-43500 first, followed by Fragnesia labeled as related. Relationships do not turn related names into aliases. Matching supports one insertion, deletion, substitution, or adjacent transposition in names of at least five normalized letters. Browser suggestions appear immediately from the index, deduplicate by CVE ID, and link to the existing live analysis page. The index contains no current scores or exploitation claims; opening an analysis still requires NVD availability.

Name and relationship mappings are sourced from [Microsoft's Dirty Frag advisory](https://www.microsoft.com/en-us/security/blog/2026/05/08/active-attack-dirty-frag-linux-vulnerability-expands-post-compromise-risk/) and [AWS's Fragnesia bulletin](https://aws.amazon.com/security/security-bulletins/2026-029-aws/).

## Minimal search and triage interface

The landing page centers on search. Results, analyses, and error pages share a compact sticky search header with keyboard autocomplete and a clear control. The light interface uses restrained status colors and an analysis panel grid: full-width priority assessment, side-by-side vulnerability overview and vendor remediation, visible CVSS/EPSS/KEV panels, and full-width sources and freshness. General supporting references remain visible in Sources and freshness; vendor remediation references have a separate expandable list there. Asset context and the handoff summary are also expandable. The grid uses three metric columns on desktop, two below 1000px, and a single column below 700px. Missing intelligence remains explicit and never becomes a zero score or a confirmed negative.

Keyword results start with 10 matches. **Load more** appends 10 on demand until NVD's reported results are exhausted. Failures leave current rows intact and allow retry. Duplicate CVEs are not appended. Returning with browser Back restores loaded rows and scroll position using optional session storage (30-minute restoration window); no recent-search history is offered. A new search starts a fresh result list. Without JavaScript, GET search, next-page links, and native analysis disclosures remain usable.

The search API adds `startIndex` (default `0`) and returns `startIndex` plus nullable `nextStartIndex` alongside its existing fields. Invalid or negative offsets return `400` with the existing error shape. The existing `limit` defaults and clamping remain unchanged. Exact CVE lookup does not paginate. Empty upstream pages terminate pagination even if a changing upstream total suggests more records. NVD results may change between requests; this is not a snapshot of the catalog.

`/demo` search and suggestions use frozen fixtures only. The independent `index.html` contains the same rendered fixture analyses, embedded CSS, and local search interactions; it can be opened directly without a backend. With JavaScript disabled it exposes all fixture analyses through anchor links. Rebuild it after changing templates, styles, fixtures, or `static/offline.js`:

```sh
uv run python scripts/build_static_demo.py
```

Run interface regression checks alongside the existing suite:

```sh
uv run pytest -q
node --test tests/search.test.cjs tests/ui.test.cjs
```
