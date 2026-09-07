"""Load local configuration once; environment variables take precedence."""

import os
from pathlib import Path

from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")

NVD_API_KEY = os.getenv("NVD_API_KEY", "")
try:
    REQUEST_TIMEOUT_MS = int(os.getenv("REQUEST_TIMEOUT_MS", "8000"))
    if REQUEST_TIMEOUT_MS <= 0:
        raise ValueError
except ValueError:
    raise ValueError("REQUEST_TIMEOUT_MS must be a positive integer") from None
