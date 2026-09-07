"""Frozen illustrative fixtures; demo pages never call upstream APIs."""

import json
from pathlib import Path

from vm_analysis.models import CveDetailResponse, SearchResponse

DATA = Path(__file__).resolve().parent / "data"
DEMO_SEARCH = SearchResponse.model_validate_json((DATA / "search.json").read_text(encoding="utf-8"))
DEMO_ANALYSES = {
    key: CveDetailResponse.model_validate(value)
    for key, value in json.loads((DATA / "analyses.json").read_text(encoding="utf-8")).items()
}
