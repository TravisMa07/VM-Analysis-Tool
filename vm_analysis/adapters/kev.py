import httpx

from vm_analysis.http import UpstreamError, fetch_json
from vm_analysis.models import KevData
from vm_analysis.utils import is_valid_cve_id, normalize_cve_id

KEV_API_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def map_kev_entry(payload: dict, cve_id: str) -> KevData:
    if any(not isinstance(item.get("cveID"), str) or not is_valid_cve_id(item["cveID"])
           for item in payload["vulnerabilities"]):
        raise UpstreamError("KEV catalog contains a record without a valid CVE identifier")
    record = next((item for item in payload["vulnerabilities"]
                   if normalize_cve_id(item.get("cveID", "")) == normalize_cve_id(cve_id)), None)
    if record is None:
        return KevData(listed=False)
    return KevData(listed=True, vendor_project=record.get("vendorProject"),
                   product=record.get("product"), vulnerability_name=record.get("vulnerabilityName"),
                   date_added=record.get("dateAdded"), required_action=record.get("requiredAction"),
                   due_date=record.get("dueDate"), notes=record.get("notes") or record.get("shortDescription"))


async def get_kev(client: httpx.AsyncClient, cve_id: str) -> KevData:
    payload = await fetch_json(client, KEV_API_URL, list_key="vulnerabilities")
    return map_kev_entry(payload, cve_id)
