import asyncio

import httpx
import pytest

from vm_analysis.adapters.epss import map_epss_response, probability
from vm_analysis.adapters.kev import map_kev_entry
from vm_analysis.adapters.nvd import map_metric_to_cvss, map_nvd_record_to_detail, map_nvd_record_to_search_result, search_nvd
from vm_analysis.http import UpstreamError, fetch_json


def test_nvd_normalization(nvd_record):
    result = map_nvd_record_to_search_result(nvd_record)
    assert result.cve_id == "CVE-2024-0001"
    assert result.cvss_base_score == 9.8
    assert result.cvss_severity == "CRITICAL"
    assert "remote code execution" in result.summary


def test_missing_optional_nvd_data():
    result = map_nvd_record_to_detail({"cve": {"id": "CVE-2023-1111"}})
    assert result.description == "No description provided by NVD."
    assert result.cwes == result.references == []
    assert result.cvss.base_score is None
    assert map_metric_to_cvss().vector is None


@pytest.mark.parametrize("version", ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"])
def test_metric_fallback(version):
    record = {"cve": {"id": "CVE-2024-0001", "metrics": {
        version: [{"cvssData": {"baseScore": 7.5}}],
    }}}
    assert map_nvd_record_to_detail(record).cvss.base_score == 7.5


def test_metric_preference_and_english(nvd_record):
    nvd_record["cve"]["metrics"]["cvssMetricV2"] = [{"cvssData": {"baseScore": 5}}]
    nvd_record["cve"]["descriptions"].insert(0, {"lang": "fr", "value": "French"})
    detail = map_nvd_record_to_detail(nvd_record)
    assert detail.cvss.base_score == 9.8
    assert detail.description.startswith("Example")


def test_epss_normalization_and_absence():
    payload = {"data": [{"cve": "CVE-2024-0001", "epss": "0.8123", "percentile": "0.9911"}]}
    result = map_epss_response("cve-2024-0001", payload)
    assert result.score == pytest.approx(0.8123)
    assert result.percentile == pytest.approx(0.9911)
    assert map_epss_response("CVE-2024-0002", payload) is None
    assert map_epss_response("CVE-2024-0001", {"data": []}) is None


@pytest.mark.parametrize("value", [None, "", "garbage", "NaN", "Infinity", "-1", "1.1"])
def test_invalid_epss_is_unknown(value):
    assert probability(value) is None


def test_zero_probability_is_valid():
    assert probability("0") == 0


@pytest.mark.parametrize("identifier", [None, "invalid", 123])
def test_invalid_enrichment_records_are_not_negative_results(identifier):
    with pytest.raises(UpstreamError):
        map_epss_response("CVE-2024-0001", {"data": [{"cve": identifier}]})
    with pytest.raises(UpstreamError):
        map_kev_entry({"vulnerabilities": [{"cveID": identifier}]}, "CVE-2024-0001")


def test_kev_normalization_and_absence():
    payload = {"vulnerabilities": [{"cveID": "CVE-2024-0001", "vendorProject": "Vendor",
                                    "shortDescription": "Short description"}]}
    listed = map_kev_entry(payload, " cve-2024-0001 ")
    assert listed.listed is True
    assert listed.vendor_project == "Vendor"
    assert listed.notes == "Short description"
    absent = map_kev_entry(payload, "CVE-2024-9999")
    assert absent.listed is False
    assert absent.vendor_project is None


@pytest.mark.parametrize("limit,expected", [(100, "25"), (0, "1"), (-5, "1"), (10, "10")])
async def test_search_limits(limit, expected):
    def handler(request):
        assert request.url.params["resultsPerPage"] == expected
        assert request.url.params["keywordSearch"] == "vendor"
        return httpx.Response(200, json={"vulnerabilities": []})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await search_nvd(client, " vendor ", limit)


@pytest.mark.parametrize("payload", [{}, [], {"data": None}, {"data": ["invalid"]}])
async def test_malformed_response_is_not_absence(payload):
    async with httpx.AsyncClient(transport=httpx.MockTransport(
        lambda request: httpx.Response(200, json=payload)
    )) as client:
        with pytest.raises(UpstreamError):
            await fetch_json(client, "https://example.test", list_key="data")


async def test_total_request_timeout(monkeypatch):
    monkeypatch.setattr("vm_analysis.http.REQUEST_TIMEOUT_MS", 10)
    async def slow(request):
        await asyncio.sleep(1)
        return httpx.Response(200, json={"data": []})
    async with httpx.AsyncClient(transport=httpx.MockTransport(slow)) as client:
        with pytest.raises(UpstreamError):
            await fetch_json(client, "https://example.test", list_key="data")
