"""Bound upstream requests and keep failures distinct from empty results."""

import asyncio

import httpx

from vm_analysis.config import REQUEST_TIMEOUT_MS


class UpstreamError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


async def fetch_json(client: httpx.AsyncClient, url: str, *, list_key: str,
                     params: dict | None = None, headers: dict | None = None) -> dict:
    try:
        async with asyncio.timeout(REQUEST_TIMEOUT_MS / 1000):
            response = await client.get(url, params=params, headers=headers)
            response.raise_for_status()
        payload = response.json()
    except httpx.HTTPStatusError as exc:
        raise UpstreamError("Upstream source returned an error", exc.response.status_code) from exc
    except (httpx.RequestError, TimeoutError, ValueError) as exc:
        raise UpstreamError("Upstream source is unavailable or returned invalid JSON") from exc
    if not isinstance(payload, dict) or not isinstance(payload.get(list_key), list):
        raise UpstreamError("Upstream source returned an unexpected response")
    if any(not isinstance(item, dict) for item in payload[list_key]):
        raise UpstreamError("Upstream source returned an unexpected record")
    return payload
