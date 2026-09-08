"""Rebuild index.html from the app's templates and frozen fixtures; no upstream calls."""
from pathlib import Path
import re
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from fastapi.testclient import TestClient
from main import app
from vm_analysis.demo import DEMO_ANALYSES

root = Path(__file__).resolve().parents[1]
with TestClient(app) as client:
    html = client.get('/demo').text
    html = re.sub(r'<script src=.*?</script>|<link rel="stylesheet"[^>]*>', '', html)
    html = html.replace('</head>', '<style>' + (root / 'static/styles.css').read_text(encoding='utf-8') + '</style></head>')
    sections = []
    for identifier in DEMO_ANALYSES:
        detail = client.get(f'/cve/{identifier}?demo=1').text
        content = re.search(r'<main[^>]*>(.*?)</main>', detail, re.S).group(1)
        content = re.sub(r'<form class="context-form".*?</form>', '<p>Asset filtering requires the live application. Confirm installed product and version against the vendor advisory.</p>', content, flags=re.S)
        sections.append(f'<section class="offline-detail" id="{identifier}">{content}</section>')
    html = re.sub(r'href="/cve/([^?]+)\?demo=1"', r'href="#\1"', html)
    html = html.replace('action="/demo"', 'action="#"').replace('class="brand" href="/demo"', 'class="brand" href="#"')
    html = html.replace('</main>', '\n'.join(sections) + '</main>')
    html = re.sub(r'<footer>.*?</footer>', '<footer>Frozen illustrative data · not current intelligence · Standalone demo</footer>', html)
    html = html.replace('<main id="content" class="page-shell">', '<main id="content" class="page-shell"><noscript>JavaScript enables fixture search. All demo results and analyses are available below.</noscript>')
    html = html.replace('</body>', '<script>' + (root / 'static/offline.js').read_text(encoding='utf-8') + '</script></body>')
    (root / 'index.html').write_text('\n'.join(line.rstrip() for line in html.splitlines()) + '\n', encoding='utf-8')
