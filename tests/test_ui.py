"""Pagination and progressive-disclosure contract checks, without upstream access."""
import copy
import re
import httpx
import pytest


def test_pagination_and_html_fallback(api, nvd_record):
    client, state = api
    calls = []
    def handler(request):
        offset = int(request.url.params['startIndex'])
        calls.append(offset)
        assert request.url.params['resultsPerPage'] == '10'
        records = []
        for i in range(offset, min(offset + 10, 23)):
            record = copy.deepcopy(nvd_record)
            record['cve']['id'] = f'CVE-2024-{i+1000}'
            records.append(record)
        return httpx.Response(200, json={'vulnerabilities': records, 'totalResults': 23})
    state['handler'] = handler
    for offset, length, next_index in [(0, 10, 10), (10, 10, 20), (20, 3, None), (30, 0, None)]:
        data = client.get('/api/search', params={'q':'openssl','startIndex':offset}).json()
        assert len(data['results']) == length
        assert data['startIndex'] == offset
        assert data['nextStartIndex'] == next_index
        assert data['totalResults'] == 23
    html = client.get('/?q=openssl&startIndex=10').text
    assert 'startIndex=20' in html
    assert 'CVE-2024-1010' in html
    assert 'data-start="10"' in html


@pytest.mark.parametrize('offset', ['-1', 'bad', '1.5', ''])
def test_invalid_offset_uses_error_contract(api, offset):
    client, _ = api
    response = client.get('/api/search', params={'q':'test','startIndex':offset})
    assert response.status_code == 400
    assert set(response.json()) == {'error'}
    assert client.get('/', params={'q':'test','startIndex':offset}).status_code == 400


def test_empty_upstream_page_stops_even_with_remaining_total(api):
    client, state = api
    state['handler'] = lambda request: httpx.Response(200, json={'vulnerabilities':[], 'totalResults':100})
    data = client.get('/api/search?q=test&startIndex=10').json()
    assert data['nextStartIndex'] is None


def test_detail_disclosure_order_and_search(api):
    client, _ = api
    html = client.get('/cve/CVE-2024-3400?demo=1').text
    headings = ['Priority assessment', 'Vulnerability overview', 'Vendor remediation', 'CVSS · Technical severity', 'EPSS · Exploitation probability', 'KEV · Known exploitation', 'Sources and freshness', 'Check your asset', 'Handoff summary']
    positions = [html.index(heading) for heading in headings]
    assert positions == sorted(positions)
    assert 'class="site-header"' in html and 'action="/demo"' in html
    assert 'copy-summary' in html
    summaries = re.findall(r'<summary>(.*?)</summary>', html)
    assert summaries[0].startswith('Vendor remediation supporting sources (')
    assert summaries[1:] == ['Check your asset', 'Handoff summary']
    sources = re.search(r'<details class="vendor-remediation-sources">(.*?)</details>', html, re.S).group(1)
    assert 'security.paloaltonetworks.com' in sources
    assert 'nvd.nist.gov' not in sources
    assert 'page-shell analysis-page' in html
    assert html.index('Sources and freshness') < html.index('<details')
    assert not re.search(r'<details[^>]*\bopen\b', html)
    context_html = client.get('/cve/CVE-2024-3400?demo=1&product=PAN-OS').text
    assert '<details class="analysis-panel optional-tool" open>' in context_html
    assert 'value="PAN-OS"' in context_html


def test_demo_search_is_local_and_empty_is_clear(api):
    client, _ = api
    html = client.get('/demo?q=3400').text
    assert 'Showing 1 of 1' in html
    assert 'data-cve="CVE-2023-4863"' not in html
    assert 'No matching CVEs' in client.get('/demo?q=nomatch').text
    assert 'action="/"' in client.get('/missing').text
