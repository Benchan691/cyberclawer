"""Pinned CVE baseline manifests. Archive bytes are never extracted as paths."""
from __future__ import annotations

import re
import sqlite3
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .client import FetchError
from .models import ListEntry, ListPage, VulnerabilityId

RELEASES_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=100"
BASELINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})_all_CVEs_at_midnight\.zip$")
RECORD_RE = re.compile(r"(?:^|/)CVE-(\d{4})-(\d{4,})\.json$")


async def baseline_asset(client: Any) -> dict[str, Any]:
    response = await client.get_json(RELEASES_URL)
    if not isinstance(response.data, list):
        raise FetchError("CVE release listing is not an array")
    candidates = []
    for release in response.data:
        for asset in release.get("assets", []):
            match = BASELINE_RE.fullmatch(str(asset.get("name", "")))
            if match:
                url = str(asset.get("browser_download_url", ""))
                target = urlparse(url)
                if target.scheme != "https" or target.netloc != "github.com" or not target.path.startswith("/CVEProject/cvelistV5/releases/download/"):
                    raise FetchError("CVE baseline download has an unexpected origin")
                stamp = datetime.fromisoformat(match.group(1)).replace(tzinfo=UTC)
                candidates.append({"url": url, "asset_id": str(asset["id"]), "timestamp": stamp.isoformat()})
    if not candidates:
        raise FetchError("No official CVE baseline archive is available in recent releases")
    return max(candidates, key=lambda item: item["timestamp"])


async def baseline_page(client: Any, task: dict[str, Any], directory: Path, provider: Any) -> ListPage:
    asset = task.get("asset")
    if not asset:
        asset = task["asset"] = await baseline_asset(client)
        # A baseline supplies coverage only up to its own creation time.
        task["until"] = asset["timestamp"]
    asset_id = asset["asset_id"]
    if not str(asset_id).isdigit():
        raise FetchError("Invalid CVE baseline asset identifier")
    directory.mkdir(parents=True, exist_ok=True)
    archive = directory / f"baseline-{asset_id}.zip"
    manifest = directory / f"baseline-{asset_id}.sqlite"
    if not manifest.exists():
        if not archive.exists():
            await client.download(asset["url"], archive)
        temporary = manifest.with_suffix(".tmp")
        temporary.unlink(missing_ok=True)
        try:
            with zipfile.ZipFile(archive) as zipped, sqlite3.connect(temporary) as database:
                database.execute("CREATE TABLE records (code TEXT PRIMARY KEY, year INTEGER, number INTEGER)")

                def rows():
                    for name in zipped.namelist():
                        match = RECORD_RE.search(name)
                        if match:
                            year, number = match.groups()
                            yield f"{year}-{number}", int(year), int(number)

                database.executemany("INSERT OR IGNORE INTO records VALUES (?, ?, ?)", rows())
                database.execute("CREATE INDEX record_order ON records (year DESC, number DESC)")
            temporary.replace(manifest)
        except (zipfile.BadZipFile, sqlite3.Error) as exc:
            temporary.unlink(missing_ok=True)
            archive.unlink(missing_ok=True)
            raise FetchError(f"Invalid CVE baseline archive: {exc}") from exc
    page = task["page"]
    size = 100
    with sqlite3.connect(manifest) as database:
        total = database.execute("SELECT COUNT(*) FROM records").fetchone()[0]
        rows = database.execute("SELECT code FROM records ORDER BY year DESC, number DESC LIMIT ? OFFSET ?", (size, (page - 1) * size)).fetchall()
    if total == 0:
        raise FetchError("CVE baseline archive contains no CVE records")
    entries = [ListEntry(identity=VulnerabilityId("CVE", code), title=f"CVE-{code}",
                         vuln_type=None, disclosure_date=None, status=None,
                         provider="cve", source_url=provider.source_url,
                         embedded_detail={"_list_summary": True, "_github_link": provider.cve_url(code)})
               for (code,) in rows]
    return ListPage(page=page, entries=entries, total_pages=(total + size - 1) // size,
                    total_records=total, exhausted=not entries)
