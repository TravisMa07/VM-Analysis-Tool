import asyncio

import httpx
import pytest

from vm_analysis.suggestions import SuggestionService


@pytest.fixture(autouse=True)
def isolated_suggestions(monkeypatch):
    monkeypatch.setattr('main.suggestion_service', SuggestionService())


def test_suggestions_api_thresholds_and_contract(api, nvd_record):
    client, state = api
    for query in ['', 'ab', 'CV', 'CVE-2024-']:
        assert client.get('/api/suggestions', params={'q': query}).json() == []
    assert client.get('/api/suggestions', params={'q': 'x' * 201}).status_code == 400
    calls = []
    def handler(request):
        calls.append(request)
        assert request.url.params['cveId'] == 'CVE-2024-0001'
        return httpx.Response(200, json={'vulnerabilities': [nvd_record] * 6})
    state['handler'] = handler
    result = client.get('/api/suggestions?q=cve-2024-0001')
    assert result.status_code == 200
    assert len(result.json()) == 1
    assert result.json()[0]['cveId'] == 'CVE-2024-0001'
    assert 'epss' not in result.json()[0]
    assert client.get('/api/suggestions?q=CVE-2024-0001').json() == result.json()
    assert client.get('/api/suggestions?q=CVE-2024-').json() == result.json()
    assert len(calls) == 1


def test_suggestions_failure_backoff(api):
    client, state = api
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(429)
    state['handler'] = handler
    assert client.get('/api/suggestions?q=openssl').status_code == 502
    assert client.get('/api/suggestions?q=windows').status_code == 502
    assert len(calls) == 1


async def test_cache_expiry_bounds_and_single_flight(nvd_record):
    now = [0]
    service = SuggestionService(clock=lambda: now[0])
    calls = []
    async def handler(request):
        calls.append(request)
        assert request.url.params['resultsPerPage'] == '4'
        await asyncio.sleep(0)
        return httpx.Response(200, json={'vulnerabilities': [nvd_record]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        first, second = await asyncio.gather(service.search(client, ' OpenSSL '), service.search(client, 'openssl'))
        assert first == second
        assert len(calls) == 1
        now[0] = 299
        await service.search(client, 'OPENSSL')
        assert len(calls) == 1
        now[0] = 300
        await service.search(client, 'openssl')
        assert len(calls) == 2
        for i in range(257):
            await service.search(client, f'product-{i}')
        assert len(service.cache) == 256
        assert 'openssl' not in service.cache
        assert not service.pending


async def test_backoff_recovers_and_preserves_cache(nvd_record):
    now = [0]
    service = SuggestionService(clock=lambda: now[0])
    failing = [False]
    def handler(request):
        return httpx.Response(503 if failing[0] else 200, json={'vulnerabilities': [nvd_record]})
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        expected = await service.search(client, 'openssl')
        failing[0] = True
        with pytest.raises(Exception):
            await service.search(client, 'windows')
        assert await service.search(client, 'openssl') == expected
        failing[0] = False
        now[0] = 15
        assert await service.search(client, 'windows') == expected

@pytest.mark.parametrize('query', ['46300', '4630', 'CVE-2026-46300', 'fragnesia', 'fragn', 'fragnesa', 'frganesia'])
def test_indexed_fragnesia_without_upstream(api, query):
    response = api[0].get('/api/suggestions', params={'q': query})
    assert response.status_code == 200
    assert response.json()[0]['cveId'] == 'CVE-2026-46300'
    assert response.json()[0]['title'] == 'Fragnesia'


@pytest.mark.parametrize('query', ['dirty frag', 'DirtyFrag', 'dirty-frag', 'dirty   frag'])
def test_direct_names_before_related(api, query):
    records = api[0].get('/api/suggestions', params={'q': query}).json()
    assert [item['cveId'] for item in records] == ['CVE-2026-43284', 'CVE-2026-43500', 'CVE-2026-46300']
    assert 'Related to Dirty Frag' in records[2]['title']


def test_index_numeric_matching_across_years_and_no_number_typos():
    from vm_analysis.search_index import indexed_matches
    from vm_analysis.models import SearchResultItem
    cached = [SearchResultItem(cve_id='CVE-2025-46300', title='Test', summary='Test')]
    assert {item.cve_id for item in indexed_matches('46300', cached)} == {'CVE-2025-46300', 'CVE-2026-46300'}
    assert indexed_matches('46301', cached) == []
    assert indexed_matches('!!!', cached) == []


def test_index_has_verified_sources_and_unique_ids():
    from vm_analysis.search_index import VULNERABILITIES
    from vm_analysis.utils import is_valid_cve_id
    assert len({item['cveId'] for item in VULNERABILITIES}) == len(VULNERABILITIES)
    for item in VULNERABILITIES:
        assert is_valid_cve_id(item['cveId'])
        assert item['sources'] and item['verifiedOn']
        assert item['label'] and item['summary']
