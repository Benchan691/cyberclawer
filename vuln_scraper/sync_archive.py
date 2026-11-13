"""Pinned CVE baseline manifests. Archive bytes are never extracted as paths."""
from __future__ import annotations

import re
import hashlib
import shutil
import sqlite3
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .client import FetchError
from .models import ListEntry, ListPage, VulnerabilityId

RELEASES_URL = "https://api.github.com/repos/CVEProject/cvelistV5/releases?per_page=100"
BASELINE_RE = re.compile(r"^(\d{4}-\d{2}-\d{2})_all_CVEs_at_midnight\.zip(?:\.zip)?$")
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
                candidates.append({"url": url, "asset_id": str(asset["id"]), "timestamp": stamp.isoformat(),
                                   "digest": asset.get("digest")})
    if not candidates:
        raise FetchError("No official CVE baseline archive is available in recent releases")
    return max(candidates, key=lambda item: item["timestamp"])


def _record_rows(archive: Path, directory: Path, asset_id: str, depth: int = 0):
    with zipfile.ZipFile(archive) as zipped:
        found = False
        nested = []
        for info in zipped.infolist():
            match = RECORD_RE.search(info.filename)
            if match:
                found = True
                year, number = match.groups()
                yield f"{year}-{number}", int(year), int(number)
            elif not info.is_dir() and info.filename.lower().endswith(".zip"):
                nested.append(info)
        if found:
            return
        if len(nested) != 1 or depth >= 2:
            raise FetchError("CVE baseline archive contains no CVE records")
        # Current official .zip.zip releases wrap cves.zip. Copy only that
        # member's bytes to our own filename; never extract archive paths.
        inner = directory / f"baseline-{asset_id}-inner-{depth + 1}.zip"
        if not inner.exists():
            temporary = inner.with_suffix(".tmp")
            with zipped.open(nested[0]) as source, temporary.open("wb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
            temporary.replace(inner)
    yield from _record_rows(inner, directory, asset_id, depth + 1)


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
        if asset.get("digest") and not task.get("verified_archive_digest"):
            checksum = hashlib.sha256()
            with archive.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    checksum.update(chunk)
            if asset["digest"] != f"sha256:{checksum.hexdigest()}":
                archive.unlink(missing_ok=True)
                raise FetchError("CVE baseline archive checksum does not match the official release")
            task["verified_archive_digest"] = asset["digest"]
        temporary = manifest.with_suffix(".tmp")
        temporary.unlink(missing_ok=True)
        try:
            with sqlite3.connect(temporary) as database:
                database.execute("CREATE TABLE records (code TEXT PRIMARY KEY, year INTEGER, number INTEGER)")
                database.executemany("INSERT OR IGNORE INTO records VALUES (?, ?, ?)",
                                     _record_rows(archive, directory, asset_id))
                database.execute("CREATE INDEX record_order ON records (year DESC, number DESC)")
            temporary.replace(manifest)
        except (zipfile.BadZipFile, sqlite3.Error, FetchError) as exc:
            temporary.unlink(missing_ok=True)
            archive.unlink(missing_ok=True)
            for inner in directory.glob(f"baseline-{asset_id}-inner-*.zip"):
                inner.unlink(missing_ok=True)
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
