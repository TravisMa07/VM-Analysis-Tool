"""Verified name mappings, with deterministic identifier and one-edit matching."""

import json
import re

from vm_analysis.config import ROOT
from vm_analysis.models import SearchResultItem

VULNERABILITIES = json.loads((ROOT / "static/vulnerability-index.json").read_text(encoding="utf-8"))


def normalize(value):
    return re.sub(r"[^a-z0-9]", "", value.lower())


def one_edit(a, b):
    if abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        differences = [i for i in range(len(a)) if a[i] != b[i]]
        return len(differences) <= 1 or (len(differences) == 2
            and differences[1] == differences[0] + 1
            and a[differences[0]] == b[differences[1]]
            and a[differences[1]] == b[differences[0]])
    shorter, longer = (a, b) if len(a) < len(b) else (b, a)
    return any(longer[:i] + longer[i + 1:] == shorter for i in range(len(longer)))


def term_score(term, query):
    value, key = normalize(term), normalize(query)
    if not key:
        return 99
    if value == key:
        return 0
    if value.startswith(key):
        return 1
    if any(normalize(word).startswith(key) for word in re.split(r"[\s-]+", term)):
        return 2
    if len(key) >= 5 and key.isalpha() and one_edit(value, key):
        return 3
    return 99


def identifier_score(cve_id, query):
    key = normalize(query)
    if key.isdigit():
        number = cve_id.rsplit("-", 1)[1]
        return 0 if key == number else 1 if number.startswith(key) else 99
    return term_score(cve_id, query)


def indexed_matches(query, cached=()):
    matches = []
    for record in VULNERABILITIES:
        score = min(identifier_score(record["cveId"], query),
                    *(term_score(term, query) for term in [record["label"], *record["aliases"]]))
        related = next((term for term in record["relatedTerms"] if term_score(term, query) < 3), None)
        title = record["label"]
        if score == 99 and related:
            score, title = 4, f"{title} — Related to {related}"
        if score < 99:
            matches.append((score, SearchResultItem(cve_id=record["cveId"], title=title,
                                                   summary=record["summary"])))
    for item in cached:
        score = identifier_score(item.cve_id, query)
        if score < 99:
            matches.append((score, item))
    result, seen = [], set()
    for _, item in sorted(matches, key=lambda match: (match[0], match[1].cve_id)):
        if item.cve_id not in seen:
            result.append(item)
            seen.add(item.cve_id)
    return result[:4]
