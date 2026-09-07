import httpx
import pytest


def upstreams(nvd_record, epss_status=200, kev_status=200):
    def handler(request):
        if request.url.host == "services.nvd.nist.gov":
            return httpx.Response(200, json={"vulnerabilities": [nvd_record], "totalResults": 1})
        if request.url.host == "api.first.org":
            return httpx.Response(epss_status, json={"data": [
                {"cve": "CVE-2024-0001", "epss": "0.9", "percentile": "0.95"},
            ]})
        if request.url.host == "www.cisa.gov":
            return httpx.Response(kev_status, json={"vulnerabilities": [
                {"cveID": "CVE-2024-0001", "vendorProject": "Vendor"},
            ]})
        raise AssertionError("Unexpected host")
    return handler


def test_detail_json_contract(api, nvd_record):
    client, state = api
    state["handler"] = upstreams(nvd_record)
    response = client.get("/api/cve/cve-2024-0001")
    assert response.status_code == 200
    data = response.json()
    assert data["cveId"] == "CVE-2024-0001"
    assert data["cvss"]["baseScore"] == 9.8
    assert data["sourceStatus"] == {"nvd": "ok", "epss": "ok", "kev": "ok"}
    assert data["kev"]["listed"] is True
    assert len(data["references"]) == 3
    assert "cve_id" not in data


def test_mismatched_nvd_identifier_is_not_enriched(api, nvd_record):
    client, state = api
    nvd_record["cve"]["id"] = "CVE-2024-9999"
    state["handler"] = upstreams(nvd_record)
    assert client.get("/api/cve/CVE-2024-0001").status_code == 502


@pytest.mark.parametrize("epss_status,kev_status", [(503, 200), (200, 503), (503, 503)])
def test_partial_failures(api, nvd_record, epss_status, kev_status):
    client, state = api
    state["handler"] = upstreams(nvd_record, epss_status, kev_status)
    response = client.get("/api/cve/CVE-2024-0001")
    assert response.status_code == 200
    data = response.json()
    assert data["sourceStatus"]["epss"] == ("error" if epss_status == 503 else "ok")
    assert data["sourceStatus"]["kev"] == ("error" if kev_status == 503 else "ok")
    if kev_status == 503:
        assert data["kev"]["listed"] is None
    if epss_status == 503:
        assert data["epss"] is None


def test_missing_enrichment_records(api, nvd_record):
    client, state = api
    def handler(request):
        if request.url.host == "services.nvd.nist.gov":
            return httpx.Response(200, json={"vulnerabilities": [nvd_record]})
        return httpx.Response(200, json={"data": [], "vulnerabilities": []})
    state["handler"] = handler
    data = client.get("/api/cve/CVE-2024-0001").json()
    assert data["sourceStatus"] == {"nvd": "ok", "epss": "not_found", "kev": "not_listed"}
    assert data["kev"]["listed"] is False


@pytest.mark.parametrize("status", [200, 404])
def test_nvd_absence_skips_enrichment(api, status):
    client, state = api
    def handler(request):
        assert request.url.host == "services.nvd.nist.gov"
        return httpx.Response(status, json={"vulnerabilities": []})
    state["handler"] = handler
    assert client.get("/api/cve/CVE-2024-0001").status_code == 404
    response = client.get("/api/search?q=CVE-2024-0001")
    assert response.status_code == 200
    assert response.json()["results"] == []


@pytest.mark.parametrize("path", ["/api/search", "/api/search?q=%20", "/api/cve/invalid"])
def test_bad_input(api, path):
    response = api[0].get(path)
    assert response.status_code == 400
    assert "error" in response.json()


@pytest.mark.parametrize("path", ["/api/search?q=test", "/api/cve/CVE-2024-0001"])
@pytest.mark.parametrize("failure", ["rate_limit", "timeout", "bad_json", "bad_shape"])
def test_upstream_failure_returns_502(api, path, failure):
    client, state = api
    def handler(request):
        if failure == "timeout":
            raise httpx.ReadTimeout("secret upstream details", request=request)
        if failure == "bad_json":
            return httpx.Response(200, text="not JSON")
        if failure == "bad_shape":
            return httpx.Response(200, json={"error": "wrong schema"})
        return httpx.Response(429)
    state["handler"] = handler
    response = client.get(path)
    assert response.status_code == 502
    assert "error" in response.json()
    assert "secret" not in response.text


def test_exact_search_and_invalid_limit(api, nvd_record):
    client, state = api
    def handler(request):
        assert request.url.params["cveId"] == "CVE-2024-0001"
        assert "keywordSearch" not in request.url.params
        return httpx.Response(200, json={"vulnerabilities": [nvd_record], "totalResults": 1})
    state["handler"] = handler
    response = client.get("/api/search", params={"q": " cve-2024-0001 ", "limit": "bad"})
    assert response.status_code == 200
    assert response.json()["mode"] == "cveId"


def test_pages_demo_static_and_docs(api):
    client, _ = api
    for path in ["/", "/demo", "/cve/CVE-2024-3400?demo=1", "/cve/CVE-2023-4863?demo=1", "/docs", "/static/styles.css", "/static/search.js"]:
        assert client.get(path).status_code == 200, path
    demo = client.get("/demo").text
    assert "?demo=1" in demo
    assert "not current intelligence" in demo
    assert client.get("/cve/CVE-2099-9999?demo=1").status_code == 404
    assert client.get("/cve/invalid").status_code == 404
    assert client.get("/missing").status_code == 404
    schema = client.get("/openapi.json").json()
    assert set(schema["paths"]) == {"/api/search", "/api/cve/{cve_id}", "/api/suggestions"}
    assert "cveId" in schema["components"]["schemas"]["CveDetailResponse"]["properties"]


def test_html_search_and_escaping(api, nvd_record):
    client, state = api
    nvd_record["cve"]["descriptions"][0]["value"] = '<script>alert("x")</script>'
    state["handler"] = upstreams(nvd_record)
    for path in ["/?q=vendor", "/cve/CVE-2024-0001"]:
        response = client.get(path)
        assert response.status_code == 200
        assert "&lt;script&gt;" in response.text
        assert '<script>alert("x")</script>' not in response.text


def test_html_search_empty_and_failure(api):
    client, state = api
    state["handler"] = lambda request: httpx.Response(200, json={"vulnerabilities": []})
    assert "No matching CVEs" in client.get("/?q=vendor").text
    assert client.get("/?q=%20").status_code == 400
    state["handler"] = lambda request: httpx.Response(503)
    response = client.get("/?q=vendor")
    assert response.status_code == 502
    assert "Unable to search NVD" in response.text
    assert client.get("/cve/CVE-2024-0001").status_code == 502


def test_html_unknown_is_not_not_listed(api, nvd_record):
    client, state = api
    state["handler"] = upstreams(nvd_record, 503, 503)
    response = client.get("/cve/CVE-2024-0001")
    assert response.status_code == 200
    assert "KEV unavailable" in response.text
    assert "Not listed" not in response.text
    assert "Intelligence is incomplete" in response.text
