import re
from datetime import datetime


def normalize_cve_id(value: str) -> str:
    return value.strip().upper()


def is_valid_cve_id(value: str) -> bool:
    return re.fullmatch(r"CVE-\d{4}-\d{4,}", normalize_cve_id(value), re.ASCII) is not None


def truncate_text(value: str, max_length: int) -> str:
    return value if len(value) <= max_length else value[:max_length - 1].rstrip() + "…"


def format_percent(value: float | None) -> str:
    return "Not available" if value is None else f"{value * 100:.2f}%"


def format_score(value: float | None) -> str:
    return "N/A" if value is None else f"{value:.1f}"


def format_date(value: str | None) -> str:
    if not value:
        return "Not available"
    try:
        date = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return f"{date:%b} {date.day}, {date.year}"
    except ValueError:
        return value
