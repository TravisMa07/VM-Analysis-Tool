"""Bounded advisory fetching and conservative, display-only fact extraction."""

import asyncio
import json
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from urllib.parse import urlparse

import httpx

from vm_analysis.models import AdvisoryCommand, CveReference, VendorGuidance
from vm_analysis.vendor_sources import candidate_vendor_reference, source_type, vendor_name

FRESH_TTL = timedelta(minutes=15)
STALE_TTL = timedelta(hours=24)
MAX_RESPONSE_BYTES = 2 * 1024 * 1024
MAX_TEXT_CHARS = 250_000
MAX_CACHE_ENTRIES = 256
_cache: dict[str, "CachedAdvisory"] = {}


@dataclass
class CachedAdvisory:
    guidance: VendorGuidance
    fetched_at: datetime
    expires_at: datetime


class AdvisoryHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.headings: list[str] = []
        self.blocks: list[str] = []
        self.code_blocks: list[str] = []
        self.json_ld: list[dict] = []
        self._tag_stack: list[str] = []
        self._buffer: list[str] = []
        self._code_buffer: list[str] | None = None
        self._script_buffer: list[str] | None = None

    def handle_starttag(self, tag, attrs):
        self._tag_stack.append(tag)
        if tag in {"pre", "code"} and self._code_buffer is None:
            self._code_buffer = []
        if tag == "script" and dict(attrs).get("type", "").lower() == "application/ld+json":
            self._script_buffer = []

    def handle_endtag(self, tag):
        if tag in {"p", "li", "td", "th", "div", "section", "article", "h1", "h2", "h3", "h4"}:
            value = clean_text(" ".join(self._buffer))
            if value:
                self.blocks.append(value)
                if tag.startswith("h"):
                    self.headings.append(value)
            self._buffer = []
        if tag in {"pre", "code"} and self._code_buffer is not None:
            value = clean_text(" ".join(self._code_buffer))
            if value:
                self.code_blocks.append(value)
            self._code_buffer = None
        if tag == "script" and self._script_buffer is not None:
            try:
                value = json.loads("".join(self._script_buffer))
                self.json_ld.extend(value if isinstance(value, list) else [value])
            except (json.JSONDecodeError, TypeError):
                pass
            self._script_buffer = None
        if self._tag_stack:
            self._tag_stack.pop()

    def handle_data(self, data):
        if self._script_buffer is not None:
            self._script_buffer.append(data)
        if self._code_buffer is not None:
            self._code_buffer.append(data)
        if self._tag_stack and self._tag_stack[-1] not in {"script", "style"}:
            self._buffer.append(data)
        if self._tag_stack and self._tag_stack[-1] == "title":
            self.title += data


def clean_text(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip()


def lines_from(document: AdvisoryHTMLParser) -> list[str]:
    return [clean_text(item) for item in document.blocks if clean_text(item)]


def flatten_structured(value) -> list[str]:
    lines = []
    if isinstance(value, dict):
        for key, item in value.items():
            if isinstance(item, (str, int, float, bool)):
                lines.append(f"{key}: {item}")
            else:
                lines.extend(flatten_structured(item))
    elif isinstance(value, list):
        for item in value:
            lines.extend(flatten_structured(item))
    return lines


def first_match(lines: list[str], patterns: tuple[str, ...]) -> str | None:
    for line in lines:
        for pattern in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                return clean_text(match.group(1)).strip(" :-")
    return None


def extract_ids(text: str) -> list[str]:
    pattern = r"\b(?:KB\d{6,8}|RHSA[- ]\d{4}:\d+|USN[- ]\d+[-:]\d+|DSA[- ]\d+[-:]\d+|SUSE-SU-\d{4}:\d+[-:]\d+)\b"
    return sorted(set(re.findall(pattern, text, re.IGNORECASE)))


def extract_packages(text: str) -> list[str]:
    pattern = r"\b(?:linux-(?:image|headers|modules)[-\w.+:]*|libwebp[-\w.+:]*|openssl[-\w.+:]*|kernel[-\w.+:]*|[A-Za-z0-9][A-Za-z0-9+_.-]*(?:-security|-updates))\b"
    return sorted(set(re.findall(pattern, text)))[:30]


def extract_commands(document: AdvisoryHTMLParser, url: str, platform: str) -> list[AdvisoryCommand]:
    commands = []
    pattern = re.compile(r"^(?:sudo\s+)?(?:apt(?:-get)?|dnf|yum|zypper|powershell|pwsh|wusa|Install-Module|Install-Package|Update-Module)\b.+$", re.IGNORECASE)
    for block in document.code_blocks:
        for line in block.splitlines():
            line = line.strip().lstrip("$>\u001b[0m ")
            if pattern.match(line) and len(line) <= 500:
                commands.append(AdvisoryCommand(command=line, platform=platform, source_url=url, confidence="high"))
    deduped = []
    seen = set()
    for command in commands:
        if command.command not in seen:
            deduped.append(command)
            seen.add(command.command)
    return deduped[:20]


def parse_advisory(url: str, body: bytes, content_type: str, fetched_at: datetime,
                   stale: bool = False, tags: list[str] | None = None) -> VendorGuidance:
    parsed = urlparse(url)
    vendor = vendor_name(parsed.hostname or "vendor")
    platform = "Vendor-supported platform"
    hostname = (parsed.hostname or "").lower()
    if "microsoft" in hostname or "msrc" in hostname:
        platform = "Windows / Microsoft"
    elif "ubuntu" in hostname:
        platform = "Ubuntu Linux"
    elif "debian" in hostname:
        platform = "Debian Linux"
    elif "redhat" in hostname:
        platform = "RHEL / Red Hat Linux"
    elif "suse" in hostname:
        platform = "SUSE Linux"

    document = AdvisoryHTMLParser()
    if "json" in content_type or url.lower().endswith(".json"):
        try:
            payload = json.loads(body.decode("utf-8", errors="replace"))
            document.blocks = [clean_text(json.dumps(payload))]
        except json.JSONDecodeError:
            document.blocks = []
    else:
        document.feed(body.decode("utf-8", errors="replace")[:MAX_TEXT_CHARS])
    lines = flatten_structured(document.json_ld) + lines_from(document)
    text = "\n".join(lines)
    affected = first_match(lines, (r"(?:affected|vulnerable|impacted)\s+(?:versions?|releases?|products?)\s*[:\-]\s*(.+)",))
    fixed = first_match(lines, (r"(?:fixed|patched|resolved|unaffected)\s+(?:in|versions?|release)?\s*[:\-]\s*(.+)",
                                r"(?:update|upgrade)\s+to\s+(.+)",))
    mitigation = first_match(lines, (r"(?:workaround|mitigation)\s*[:\-]\s*(.+)",))
    remediation = first_match(lines, (r"(?:solution|remediation|recommendation|update|fix)\s*[:\-]\s*(.+)",))
    if not remediation:
        remediation = fixed or "Review the official advisory and apply the vendor's fixed release or update."
    reboot_match = re.search(r"\b(reboot|restarting|restart required|reboot required)\b", text, re.IGNORECASE)
    exploit_match = re.search(r"(known exploited|actively exploited|exploitation in the wild)", text, re.IGNORECASE)
    packages = extract_packages(text)
    identifiers = extract_ids(text)
    commands = extract_commands(document, url, platform)
    extracted_count = sum(bool(value) for value in (affected, fixed, mitigation, packages, identifiers, commands))
    status = "stale" if stale else "extracted" if extracted_count >= 2 else "partial" if extracted_count else "error"
    confidence = "high" if extracted_count >= 4 else "medium" if extracted_count >= 2 else "low" if extracted_count else "none"
    warnings = [] if extracted_count else ["The page was reachable but no structured remediation facts were confidently identified."]
    expires_at = fetched_at + (STALE_TTL if stale else FRESH_TTL)
    return VendorGuidance(
        cve_id="", vendor=vendor, product="Affected product from advisory", platform=platform,
        title=clean_text(document.title) or (document.headings[0] if document.headings else None),
        component=None, affected_versions=affected, fixed_version=fixed, advisory_url=url,
        remediation=remediation, mitigation=mitigation, verified_on=fetched_at.date().isoformat(),
        confidence="needs_review", applicability="needs_asset_context",
        automated=True, packages=packages, update_identifiers=identifiers, commands=commands,
        reboot_required=bool(reboot_match) if reboot_match else None,
        exploitation_status=exploit_match.group(1) if exploit_match else None,
        extraction_confidence=confidence, extraction_warnings=warnings,
        fetched_at=fetched_at.isoformat(), expires_at=expires_at.isoformat(), stale=stale,
        advisory_status=status, source_section=document.headings[0] if document.headings else None,
        source_type=source_type(tags or [], url),
    )


async def fetch_advisory(client: httpx.AsyncClient, cve_id: str, reference: CveReference) -> VendorGuidance:
    now = datetime.now(timezone.utc)
    cached = _cache.get(reference.url)
    if cached and now <= cached.expires_at:
        return cached.guidance.model_copy(update={"cve_id": cve_id, "stale": False, "advisory_status": "extracted"})
    try:
        response = await client.get(reference.url, follow_redirects=True, headers={"Accept": "text/html, application/json"})
        original_host = (urlparse(reference.url).hostname or "").lower().removeprefix("www.")
        final_host = (response.url.host or "").lower().removeprefix("www.")
        same_vendor = final_host == original_host or final_host.endswith("." + original_host)
        content_type = response.headers.get("content-type", "").lower()
        supported_type = "html" in content_type or "json" in content_type or not content_type
        if response.url.scheme != "https" or not same_vendor or not supported_type or len(response.content) > MAX_RESPONSE_BYTES:
            raise ValueError("unsafe redirect or oversized advisory")
        if response.status_code >= 400:
            raise ValueError(f"vendor returned HTTP {response.status_code}")
        guidance = parse_advisory(reference.url, response.content, response.headers.get("content-type", ""), now,
                                  tags=reference.tags)
        guidance = guidance.model_copy(update={"cve_id": cve_id})
        _cache[reference.url] = CachedAdvisory(guidance, now, now + FRESH_TTL)
        if len(_cache) > MAX_CACHE_ENTRIES:
            del _cache[next(iter(_cache))]
        return guidance
    except (httpx.HTTPError, asyncio.TimeoutError, TimeoutError, ValueError) as exc:
        if cached and now - cached.expires_at <= STALE_TTL:
            return cached.guidance.model_copy(update={"cve_id": cve_id, "stale": True, "advisory_status": "stale",
                                                      "extraction_warnings": [f"Fresh fetch failed: {type(exc).__name__}"]})
        return VendorGuidance(cve_id=cve_id, vendor=vendor_name(urlparse(reference.url).hostname or "vendor"),
                              product="Affected product from advisory", platform="Vendor-supported platform",
                              advisory_url=reference.url, remediation="Open the official advisory for authoritative update instructions.",
                              verified_on="NVD reference", source_type=source_type(reference.tags, reference.url),
                              advisory_status="error", extraction_warnings=["Vendor advisory could not be fetched."])


async def enrich_vendor_guidance(client: httpx.AsyncClient, cve_id: str,
                                references: list[CveReference]) -> tuple[list[VendorGuidance], str]:
    candidates = [ref for ref in references if candidate_vendor_reference(ref)]
    if not candidates:
        return [], "not_available"
    results = await asyncio.gather(*(fetch_advisory(client, cve_id, ref) for ref in candidates))
    statuses = {item.advisory_status for item in results}
    if statuses == {"extracted"}:
        status = "extracted"
    elif "stale" in statuses and statuses <= {"stale"}:
        status = "stale"
    elif statuses == {"error"}:
        status = "error"
    else:
        status = "partial" if "extracted" in statuses or "partial" in statuses else "discovered"
    return results, status


def clear_advisory_cache() -> None:
    _cache.clear()
