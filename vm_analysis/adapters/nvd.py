import httpx

from vm_analysis.config import NVD_API_KEY
from vm_analysis.http import UpstreamError, fetch_json
from vm_analysis.models import CvssData, NvdDetail, SearchResponse, SearchResultItem
from vm_analysis.utils import is_valid_cve_id, normalize_cve_id, truncate_text

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def english_value(values: list[dict]) -> str | None:
    entries = [entry for entry in values if entry.get("value")]
    preferred = next((entry for entry in entries if entry.get("lang") == "en"), None)
    return (preferred or entries[0])["value"].strip() if entries else None


def map_metric_to_cvss(metric: dict | None = None) -> CvssData:
    metric = metric or {}
    data = metric.get("cvssData") or {}
    return CvssData(
        version=data.get("version"), vector=data.get("vectorString"),
        base_score=data.get("baseScore"), base_severity=data.get("baseSeverity"),
        exploitability_score=metric.get("exploitabilityScore"),
        impact_score=metric.get("impactScore"),
    )


def map_nvd_record_to_detail(record: dict) -> NvdDetail:
    cve = record.get("cve") or {}
    if not isinstance(cve.get("id"), str) or not is_valid_cve_id(cve["id"]):
        raise UpstreamError("NVD record is missing a valid CVE identifier")
    metrics = cve.get("metrics") or {}
    preferred = (metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30")
                 or metrics.get("cvssMetricV2") or [None])[0]
    cwes = [english_value(item.get("description") or []) for item in cve.get("weaknesses") or []]
    return NvdDetail(
        cve_id=cve["id"],
        description=english_value(cve.get("descriptions") or []) or "No description provided by NVD.",
        published=cve.get("published"), last_modified=cve.get("lastModified"),
        cwes=[value for value in cwes if value],
        references=[ref for ref in cve.get("references") or [] if ref.get("url")],
        cvss=map_metric_to_cvss(preferred),
    )


def map_nvd_record_to_search_result(record: dict) -> SearchResultItem:
    detail = map_nvd_record_to_detail(record)
    title = detail.description.split(".")[0].strip() or detail.description
    return SearchResultItem(
        cve_id=detail.cve_id, title=truncate_text(title, 100),
        summary=truncate_text(detail.description, 220), published=detail.published,
        last_modified=detail.last_modified, cvss_base_score=detail.cvss.base_score,
        cvss_severity=detail.cvss.base_severity,
    )


async def request_nvd(client: httpx.AsyncClient, params: dict) -> dict:
    try:
        return await fetch_json(client, NVD_API_URL, list_key="vulnerabilities", params=params,
                                headers={"apiKey": NVD_API_KEY} if NVD_API_KEY else None)
    except UpstreamError as exc:
        if exc.status == 404:
            return {"vulnerabilities": [], "totalResults": 0}
        raise


async def search_nvd(client: httpx.AsyncClient, query: str, limit: int = 10) -> SearchResponse:
    query = query.strip()
    mode = "cveId" if is_valid_cve_id(query) else "keyword"
    params = ({"cveId": normalize_cve_id(query)} if mode == "cveId" else
              {"keywordSearch": query, "resultsPerPage": min(25, max(1, limit))})
    payload = await request_nvd(client, params)
    results = [map_nvd_record_to_search_result(record) for record in payload["vulnerabilities"]]
    return SearchResponse(query=query, mode=mode, results=results,
                          total_results=payload.get("totalResults", len(results)))


async def get_nvd_cve(client: httpx.AsyncClient, cve_id: str) -> NvdDetail | None:
    payload = await request_nvd(client, {"cveId": normalize_cve_id(cve_id)})
    records = payload["vulnerabilities"]
    if not records:
        return None
    detail = map_nvd_record_to_detail(records[0])
    if normalize_cve_id(detail.cve_id) != normalize_cve_id(cve_id):
        raise UpstreamError("NVD returned a different CVE than requested")
    return detail
