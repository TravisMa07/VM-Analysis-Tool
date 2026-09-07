import math

import httpx

from vm_analysis.models import EpssData
from vm_analysis.http import UpstreamError, fetch_json
from vm_analysis.utils import is_valid_cve_id, normalize_cve_id

EPSS_API_URL = "https://api.first.org/data/v1/epss"


def probability(value: str | float | None) -> float | None:
    try:
        number = float(value)
        return number if math.isfinite(number) and 0 <= number <= 1 else None
    except (ValueError, TypeError):
        return None


def map_epss_response(cve_id: str, payload: dict) -> EpssData | None:
    if any(not isinstance(item.get("cve"), str) or not is_valid_cve_id(item["cve"])
           for item in payload["data"]):
        raise UpstreamError("EPSS response contains a record without a valid CVE identifier")
    record = next((item for item in payload["data"]
                   if normalize_cve_id(item.get("cve", "")) == normalize_cve_id(cve_id)), None)
    if record is None:
        return None
    return EpssData(cve_id=normalize_cve_id(record["cve"]), score=probability(record.get("epss")),
                    percentile=probability(record.get("percentile")), date=record.get("date"))


async def get_epss(client: httpx.AsyncClient, cve_id: str) -> EpssData | None:
    payload = await fetch_json(client, EPSS_API_URL, list_key="data",
                               params={"cve": normalize_cve_id(cve_id)})
    return map_epss_response(cve_id, payload)
