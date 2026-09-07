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
    for attempt in range(3):
        try:
            async with asyncio.timeout(REQUEST_TIMEOUT_MS / 1000):
                response = await client.get(url, params=params, headers=headers)
                response.raise_for_status()
            payload = response.json()
            break
        except httpx.HTTPStatusError as exc:
            # Rate limits are handled by the caller's circuit breaker/cache policy;
            # retry only transient upstream server failures here.
            retryable = exc.response.status_code >= 500
            if retryable and attempt < 2:
                await asyncio.sleep(0.05 * (attempt + 1))
                continue
            raise UpstreamError("Upstream source returned an error", exc.response.status_code) from exc
        except (httpx.RequestError, TimeoutError) as exc:
            if attempt < 2:
                await asyncio.sleep(0.05 * (attempt + 1))
                continue
            raise UpstreamError("Upstream source is unavailable or returned invalid JSON") from exc
        except ValueError as exc:
            raise UpstreamError("Upstream source is unavailable or returned invalid JSON") from exc
    else:
        raise UpstreamError("Upstream source is unavailable")
    if not isinstance(payload, dict) or not isinstance(payload.get(list_key), list):
        raise UpstreamError("Upstream source returned an unexpected response")
    if any(not isinstance(item, dict) for item in payload[list_key]):
        raise UpstreamError("Upstream source returned an unexpected record")
    return payload
