"""FastAPI entrypoint: HTML pages and JSON APIs share the same Python services."""

import logging
from typing import Annotated

import httpx
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException

from vm_analysis.adapters.nvd import search_nvd
from vm_analysis.assessment import assess
from vm_analysis.config import REQUEST_TIMEOUT_MS, ROOT
from vm_analysis.demo import DEMO_ANALYSES, DEMO_SEARCH
from vm_analysis.models import CveDetailResponse, ErrorResponse, SearchResponse
from vm_analysis.service import get_cve_analysis
from vm_analysis.utils import format_date, format_percent, format_score, is_valid_cve_id, normalize_cve_id

app = FastAPI(title="VM Analysis Tool", version="0.2.0",
              description="Search NVD and combine CVSS, FIRST EPSS, and CISA KEV intelligence.")
app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")
templates = Jinja2Templates(directory=ROOT / "templates")
templates.env.filters.update(date=format_date, percent=format_percent, score=format_score)
logger = logging.getLogger(__name__)


async def get_client():
    # Request-scoped ownership also works on hosts that do not run ASGI lifespan.
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT_MS / 1000, follow_redirects=True,
                                 headers={"Accept": "application/json"}) as client:
        yield client


Client = Annotated[httpx.AsyncClient, Depends(get_client)]
API_ERRORS = {code: {"model": ErrorResponse} for code in (400, 404, 502)}


@app.exception_handler(StarletteHTTPException)
async def http_error(request: Request, exc: StarletteHTTPException):
    if request.url.path.startswith("/api/"):
        return JSONResponse({"error": str(exc.detail)}, status_code=exc.status_code, headers=exc.headers)
    return templates.TemplateResponse(request=request, name="error.html",
                                      context={"message": str(exc.detail), "status": exc.status_code},
                                      status_code=exc.status_code, headers=exc.headers)


async def run_search(client: httpx.AsyncClient, q: str, limit: str) -> SearchResponse:
    query = q.strip()
    if not query:
        raise HTTPException(400, "The q query parameter is required.")
    try:
        parsed_limit = int(limit)
    except ValueError:
        parsed_limit = 10
    try:
        return await search_nvd(client, query, parsed_limit)
    except Exception as exc:
        logger.warning("NVD search failed (%s)", type(exc).__name__)
        raise HTTPException(502, "Unable to search NVD at this time. Please try again.") from exc


async def load_analysis(client: httpx.AsyncClient, cve_id: str) -> CveDetailResponse:
    if not is_valid_cve_id(cve_id):
        raise HTTPException(400, "The supplied CVE ID is invalid.")
    try:
        result = await get_cve_analysis(client, normalize_cve_id(cve_id))
    except Exception as exc:
        logger.warning("NVD detail failed (%s)", type(exc).__name__)
        raise HTTPException(502, "Unable to load the CVE analysis right now. Please try again.") from exc
    if result is None:
        raise HTTPException(404, "The requested CVE was not found in NVD.")
    return result


@app.get("/api/search", response_model=SearchResponse, responses=API_ERRORS)
async def api_search(client: Client, q: str = "", limit: str = "10"):
    """Search by exact CVE ID or keyword; return at most 25 keyword matches."""
    return await run_search(client, q, limit)


@app.get("/api/cve/{cve_id}", response_model=CveDetailResponse, responses=API_ERRORS)
async def api_cve(cve_id: str, client: Client):
    """Require NVD; return partial analysis if EPSS or KEV is unavailable."""
    return await load_analysis(client, cve_id)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def home(request: Request, client: Client, q: str | None = None):
    results, error, status = None, None, 200
    if q is not None:
        try:
            results = await run_search(client, q, "10")
        except HTTPException as exc:
            error, status = exc.detail, exc.status_code
    return templates.TemplateResponse(request=request, name="search.html",
                                      context={"query": q or "", "results": results,
                                               "error": error, "demo": False}, status_code=status)


@app.get("/demo", response_class=HTMLResponse, include_in_schema=False)
async def demo(request: Request):
    return templates.TemplateResponse(request=request, name="search.html",
                                      context={"results": DEMO_SEARCH, "demo": True})


@app.get("/cve/{cve_id}", response_class=HTMLResponse, include_in_schema=False)
async def detail(request: Request, cve_id: str, client: Client, demo: str = ""):
    if not is_valid_cve_id(cve_id):
        raise HTTPException(404, "The supplied CVE ID is invalid.")
    if demo == "1":
        cve = DEMO_ANALYSES.get(normalize_cve_id(cve_id))
        if cve is None:
            raise HTTPException(404, "This CVE is not in the demo dataset.")
    else:
        cve = await load_analysis(client, cve_id)
    kev_label = ("KEV unavailable" if cve.source_status.kev == "error" else
                 "Listed in KEV" if cve.kev.listed else "Not listed")
    return templates.TemplateResponse(request=request, name="detail.html",
                                      context={"cve": cve, "assessment": assess(cve),
                                               "kev_label": kev_label, "demo": demo == "1"})
