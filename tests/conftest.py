import httpx
import pytest
from fastapi.testclient import TestClient

from main import app, get_client


@pytest.fixture
def api():
    """Fail closed on unexpected network use; each test supplies its upstreams."""
    def unexpected(request):
        raise AssertionError(f"Unexpected upstream call: {request.url}")

    state = {"handler": unexpected}

    async def mock_client():
        transport = httpx.MockTransport(lambda request: state["handler"](request))
        async with httpx.AsyncClient(transport=transport) as client:
            yield client

    app.dependency_overrides[get_client] = mock_client
    with TestClient(app) as client:
        yield client, state
    app.dependency_overrides.clear()


@pytest.fixture
def nvd_record():
    return {"cve": {
        "id": "CVE-2024-0001",
        "descriptions": [{"lang": "en", "value": "Example remote code execution flaw."}],
        "metrics": {"cvssMetricV31": [{"cvssData": {
            "version": "3.1", "baseScore": 9.8, "baseSeverity": "CRITICAL",
        }}]},
    }}
