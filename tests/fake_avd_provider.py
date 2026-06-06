from __future__ import annotations

import re
from dataclasses import dataclass

from vuln_scraper.models import DetailRecord, ListEntry, ListPage, VulnerabilityId


@dataclass(frozen=True, slots=True)
class FakeAvdProvider:
    key: str = "fake_avd"
    source_url: str = "https://avd.aliyun.com/high-risk/list"
    default_mongo_collection: str = "avd"
    browser_fallback: bool = False
    content_type: str = "html"
    default_request_delay: float = 0.0
    stop_on_first_known: bool = False

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str:
        return f"https://avd.aliyun.com/high-risk/list?page={max(1, page)}"

    def detail_url(self, identity_display: str) -> str:
        return f"https://avd.aliyun.com/detail?id={identity_display}"

    def parse_list(self, content: str, *, page: int) -> ListPage:
        rows = re.findall(r"<tr>(.*?)</tr>", content, flags=re.DOTALL)
        entries: list[ListEntry] = []
        for row in rows:
            if "<th>" in row:
                continue
            cells = re.findall(r"<td>(.*?)</td>", row, flags=re.DOTALL)
            if len(cells) < 5:
                continue
            identity_text = _strip_tags(cells[0])
            code = identity_text.removeprefix("AVD-").strip()
            if not code:
                continue
            entries.append(
                ListEntry(
                    identity=VulnerabilityId(type="AVD", code=code),
                    title=_strip_tags(cells[1]),
                    vuln_type=_strip_tags(cells[2]),
                    disclosure_date=_strip_tags(cells[3]),
                    status=_strip_tags(cells[4]),
                    provider="avd",
                    source_url=self.source_url,
                )
            )
        return ListPage(page=page, entries=entries, total_pages=2, total_records=4)

    def parse_detail(self, content: str) -> DetailRecord:
        title = _first_match(content, r'<span class="header__title__text">(.*?)</span>')
        cve_id = _first_match(title or "", r"(CVE-\d{4}-\d{4,})")
        return DetailRecord(
            cve_id=cve_id,
            danger_level=_first_match(content, r'<span class="badge btn-primary">(.*?)</span>'),
            description=_first_match(content, r'<div class="text-detail">(.*?)</div>'),
        )


def _strip_tags(value: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"<.*?>", "", value, flags=re.DOTALL)).strip()


def _first_match(value: str, pattern: str) -> str | None:
    match = re.search(pattern, value, flags=re.DOTALL)
    if not match:
        return None
    text = _strip_tags(match.group(1))
    return text or None
