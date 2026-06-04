from __future__ import annotations

from datetime import datetime
from typing import Any

from vuln_scraper.client import ScraperClient
from vuln_scraper.scrapers.cve.provider import CVEProvider


class NVDClient:
    def __init__(self, client: ScraperClient, provider: CVEProvider | None = None) -> None:
        self.client = client
        self.provider = provider or CVEProvider()

    async def get_cve(self, cve_id: str) -> Any:
        result = await self.client.get_json(
            self.provider.detail_url(cve_id),
            headers=self.provider.request_headers(),
        )
        return result.data

    async def list_modified(
        self,
        start: datetime | str,
        end: datetime | str,
        *,
        start_index: int = 0,
        results_per_page: int | None = None,
    ) -> Any:
        url = self.provider.modified_url(
            _format_datetime(start),
            _format_datetime(end),
            start_index=start_index,
        )
        if results_per_page is not None:
            url = url.replace("resultsPerPage=2000", f"resultsPerPage={results_per_page}")
        result = await self.client.get_json(url, headers=self.provider.request_headers())
        return result.data


def _format_datetime(value: datetime | str) -> str:
    if isinstance(value, str):
        return value
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")
