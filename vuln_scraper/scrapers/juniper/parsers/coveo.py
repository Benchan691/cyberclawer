from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

from vuln_scraper.models import ListEntry, ListPage, VulnerabilityId
from vuln_scraper.scrapers.juniper.config import BASE_URL, PAGE_SIZE, SOURCE_URL
from vuln_scraper.scrapers.juniper.parsers.detail import (
    ARTICLE_ID_RE,
    CVE_RE,
    JuniperDetailRecord,
    _iso_date,
    _lines,
    _normalize_key,
    strip_html,
)

def parse_coveo_list(
    payload: object,
    *,
    page: int,
    provider: str = "juniper",
    source_url: str | None = SOURCE_URL,
) -> ListPage:
    if not isinstance(payload, dict):
        raise TypeError("Coveo list payload must be a dict")
    entries: list[ListEntry] = []
    seen: set[str] = set()
    for hit in payload.get("results") or []:
        entry = _entry_from_hit(hit, provider=provider, source_url=source_url)
        if entry is not None and entry.identity.code not in seen:
            entries.append(entry)
            seen.add(entry.identity.code)

    total_records = payload.get("totalCount")
    if total_records is None:
        total_records = len(entries)
    total_pages = max(1, (int(total_records) + PAGE_SIZE - 1) // PAGE_SIZE) if total_records else None
    return ListPage(
        page=page,
        entries=entries,
        total_pages=total_pages,
        total_records=int(total_records) if total_records is not None else None,
    )


def parse_coveo_detail(payload: object) -> JuniperDetailRecord:
    if not isinstance(payload, dict):
        raise TypeError("Coveo detail payload must be a dict")
    results = payload.get("results") or []
    if not results:
        raise ValueError("Coveo detail payload has no results")
    return _detail_from_hit(results[0])


def _entry_from_hit(hit: dict, *, provider: str, source_url: str | None) -> ListEntry | None:
    raw = hit.get("raw") or {}
    detail_url = raw.get("sfcustomer_url__c") or hit.get("clickUri") or ""
    detail_url = urljoin(BASE_URL, str(detail_url)) if detail_url else ""
    code = _article_id(detail_url, raw.get("sfcec_documentid__c"), hit.get("title"), raw.get("sftitle"))
    if not code:
        return None

    title = _title(raw.get("sftitle") or hit.get("title"), code)
    if not title:
        return None

    published_date = _iso_date(str(raw.get("sflastpublisheddate") or "")) or None
    article_type = raw.get("sfrecordtypename") or "Security Advisories"
    summary = hit.get("excerpt") or raw.get("sfcec_problem__c")

    return ListEntry(
        identity=VulnerabilityId(type="JUNIPER", code=code),
        title=title,
        vuln_type=str(article_type),
        disclosure_date=published_date,
        status=str(article_type),
        provider=provider,
        source_url=source_url,
        embedded_detail={
            "_list_summary": True,
            "article_id": code,
            "article_type": article_type,
            "source_name": "Knowledge",
            "published_date": published_date,
            "summary": strip_html(summary) if isinstance(summary, str) else summary,
            "reference_links": [detail_url] if detail_url else [],
            "slug": raw.get("sfurlname"),
        },
    )


def _detail_from_hit(hit: dict) -> JuniperDetailRecord:
    raw = hit.get("raw") or {}
    sections = {
        "Problem": strip_html(raw.get("sfcec_problem__c")),
        "Products Affected": strip_html(raw.get("sfcec_product_affected__c")),
        "CVSS Score": strip_html(raw.get("sfcec_cvss_score__c")),
        "Severity Assessment": strip_html(raw.get("sfcec_severity_assessment__c")),
        "Solution": strip_html(raw.get("sfcec_solution__c")),
        "Workaround": strip_html(raw.get("sfcec_workaround__c")),
        "Modification History": strip_html(raw.get("sfcec_modification_history__c")),
        "Related Links": strip_html(raw.get("sfcec_related_links__c")),
    }
    sections = {key: value for key, value in sections.items() if value}
    text = "\n".join(str(value) for value in sections.values())
    title = _title(raw.get("sftitle") or hit.get("title"), raw.get("sfcec_documentid__c") or "")
    detail_url = raw.get("sfcustomer_url__c") or hit.get("clickUri")
    links = [urljoin(BASE_URL, str(detail_url))] if detail_url else []

    fields = {
        "article_type": raw.get("sfrecordtypename"),
        "source_name": "Knowledge",
        "published": raw.get("sflastpublisheddate"),
        "updated": raw.get("sflastmodifieddate"),
        "severity": raw.get("sfcec_severity_level__c"),
    }
    normalized_fields = {_normalize_key(key): str(value) if value is not None else None for key, value in fields.items()}

    return JuniperDetailRecord(
        article_id=_article_id("", raw.get("sfcec_documentid__c"), title, None),
        title=title,
        article_type=raw.get("sfrecordtypename") or "Security Advisories",
        source_name="Knowledge",
        published_date=_iso_date(str(raw.get("sflastpublisheddate") or "")),
        updated_date=_iso_date(str(raw.get("sflastmodifieddate") or "")),
        summary=strip_html(hit.get("excerpt")) if hit.get("excerpt") else None,
        description=sections.get("Problem"),
        solution=sections.get("Solution"),
        workaround=sections.get("Workaround"),
        products=_lines(sections.get("Products Affected")),
        cve_ids=_cve_ids(text),
        reference_links=links,
        raw_fields=normalized_fields,
        raw_sections={_normalize_key(key): str(value) for key, value in sections.items()},
    )


def _article_id(url: str, *texts: object | None) -> str | None:
    for text in texts:
        if not text:
            continue
        match = ARTICLE_ID_RE.search(str(text))
        if match:
            return match.group(0).upper()
    path = urlparse(urljoin(BASE_URL, url)).path.rstrip("/")
    slug = path.rsplit("/", 1)[-1]
    match = ARTICLE_ID_RE.search(slug)
    return match.group(0).upper() if match else None


def _title(value: object | None, code: str) -> str | None:
    if not value:
        return None
    text = str(value).strip()
    if code:
        text = re.sub(rf"^\s*{re.escape(str(code))}\s*[-:]\s*", "", text, flags=re.IGNORECASE).strip()
    return text or None


def _cve_ids(text: str) -> list[str]:
    result: list[str] = []
    for cve_id in CVE_RE.findall(text):
        normalized = cve_id.upper()
        if normalized not in result:
            result.append(normalized)
    return result


