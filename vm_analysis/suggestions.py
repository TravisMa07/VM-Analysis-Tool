"""Small, process-local autocomplete cache; never enrich suggestion records."""

import asyncio
import re
import time
from collections import OrderedDict

import httpx

from vm_analysis.adapters.nvd import search_nvd
from vm_analysis.models import SearchResultItem
from vm_analysis.utils import is_valid_cve_id
from vm_analysis.search_index import indexed_matches


class SuggestionService:
    def __init__(self, clock=time.monotonic):
        self.clock = clock
        self.cache = OrderedDict()
        self.pending = {}
        self.backoff_until = 0

    async def search(self, client: httpx.AsyncClient, query: str) -> list[SearchResultItem]:
        key = " ".join(query.lower().split())
        if len(key) < 3:
            return []
        now = self.clock()
        for old_key, (expires, _) in list(self.cache.items()):
            if expires <= now:
                del self.cache[old_key]
        indexed = indexed_matches(key, [item for _, items in self.cache.values() for item in items])
        if indexed:
            return indexed
        if key in self.cache:
            self.cache.move_to_end(key)
            return self.cache[key][1]
        if key.isdigit() or (re.fullmatch(r"cve(?:-[0-9]*(?:-[0-9]*)?)?", key) and not is_valid_cve_id(key)):
            return []
        if now < self.backoff_until:
            raise RuntimeError("Live suggestions are temporarily unavailable")
        if key not in self.pending:
            self.pending[key] = asyncio.create_task(self._fetch(client, key))
        task = self.pending[key]
        try:
            return await asyncio.shield(task)
        except asyncio.CancelledError:
            # Keep the request-owned HTTP client alive until shared work finishes.
            await asyncio.gather(task, return_exceptions=True)
            raise

    async def _fetch(self, client, key):
        try:
            response = await search_nvd(client, key, 4)
            items = list({item.cve_id: item for item in response.results}.values())[:4]
            self.cache[key] = (self.clock() + 300, items)
            while len(self.cache) > 256:
                self.cache.popitem(last=False)
            return items
        except Exception:
            self.backoff_until = self.clock() + 15
            raise
        finally:
            self.pending.pop(key, None)


suggestion_service = SuggestionService()
