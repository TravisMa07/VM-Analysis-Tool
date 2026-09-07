# VM Analysis Tool

A Python/FastAPI application for searching vulnerabilities and reviewing NVD CVE/CVSS data, FIRST EPSS scores, and CISA KEV status together.

The application uses server-rendered HTML and CSS. React, Next.js, TypeScript, and a Node build are no longer required. A small optional JavaScript file displays search progress; the search form works without JavaScript.

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
                           |
                           v
                  Pydantic response model
                           |
                           +-- JSON response for API clients
                           +-- assessment rules + Jinja HTML for the browser
```

- `vm_analysis/adapters/` contains one integration per source. Adapters translate external JSON into the application's data models.
- `vm_analysis/service.py` combines data and records each source's status. It skips enrichment when NVD has no record.
- `vm_analysis/assessment.py` contains independently testable prioritization rules. Templates only present their results.
- `vm_analysis/models.py` defines response data with Pydantic. Python uses snake_case; public JSON uses camelCase for compatibility.
- `templates/` contains HTML pages; `static/` holds the existing responsive styling and optional search feedback.
- `vm_analysis/data/` contains frozen illustrative demo fixtures. Demo pages do not fetch upstream data; their scores/catalog status are not current intelligence.

Each request owns an HTTPX async client. EPSS and KEV requests overlap using `asyncio.gather`, so one enrichment does not wait for the other. The client closes after the request. There is no database, login, background worker, or persistent cache.

## API

| Route | Behavior |
| --- | --- |
| `GET /api/search?q=<query>&limit=10` | Exact CVE lookup or keyword search; keyword limit clamped to 1-25 |
| `GET /api/cve/<CVE-ID>` | NVD metadata enriched with EPSS and KEV |

CVE identifiers are trimmed and normalized to uppercase. Empty search queries and invalid API CVE IDs return `400`. Missing NVD detail records return `404`; no search matches return `200` with an empty results list. NVD failures return `502`. Errors retain the `{"error": "message"}` shape.

EPSS or KEV failure does not discard a valid NVD record: the response is `200`, with the failing source marked `error` in `sourceStatus`.

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

The NVD metric preference remains CVSS 3.1, then 3.0, then 2.0. CVSS 4.0 support, pagination beyond the first result page, catalog caching, retries, and asset-aware prioritization are future work. Each live analysis downloads the KEV catalog; public source latency and rate limits affect availability.

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
