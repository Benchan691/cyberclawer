from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

from vuln_scraper.models import normalize_cve_code


@dataclass(slots=True)
class GitHubAdvisoryDetailRecord:
    ghsa_id: str | None = None
    cve_id: str | None = None
    cve_ids: list[str] = field(default_factory=list)
    summary: str | None = None
    description: str | None = None
    advisory_type: str | None = None
    severity: str | None = None
    html_url: str | None = None
    api_url: str | None = None
    repository_advisory_url: str | None = None
    source_code_location: str | None = None
    identifiers: list[dict[str, Any]] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    published_at: str | None = None
    updated_at: str | None = None
    github_reviewed_at: str | None = None
    nvd_published_at: str | None = None
    withdrawn_at: str | None = None
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    cvss: dict[str, Any] = field(default_factory=dict)
    cvss_severities: dict[str, Any] = field(default_factory=dict)
    cwes: list[dict[str, Any]] = field(default_factory=list)
    epss: dict[str, Any] = field(default_factory=dict)
    credits: list[dict[str, Any]] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def parse_advisory_response(data: Any) -> GitHubAdvisoryDetailRecord:
    payload = _coerce_json(data)
    advisory = _extract_advisory(payload)
    if advisory is None:
        raise ValueError("GitHub advisory response did not contain advisory data")
    return record_from_advisory(advisory)


def record_from_advisory(advisory: dict[str, Any]) -> GitHubAdvisoryDetailRecord:
    cve_ids = _cve_ids(advisory)
    return GitHubAdvisoryDetailRecord(
        ghsa_id=_optional_str(advisory.get("ghsa_id")),
        cve_id=cve_ids[0] if cve_ids else None,
        cve_ids=cve_ids,
        summary=_optional_str(advisory.get("summary")),
        description=_optional_str(advisory.get("description")),
        advisory_type=_optional_str(advisory.get("type")),
        severity=_optional_str(advisory.get("severity")),
        html_url=_optional_str(advisory.get("html_url")),
        api_url=_optional_str(advisory.get("url")),
        repository_advisory_url=_optional_str(advisory.get("repository_advisory_url")),
        source_code_location=_optional_str(advisory.get("source_code_location")),
        identifiers=_list_of_dicts(advisory.get("identifiers")),
        references=_list_of_strings(advisory.get("references")),
        published_at=_optional_str(advisory.get("published_at")),
        updated_at=_optional_str(advisory.get("updated_at")),
        github_reviewed_at=_optional_str(advisory.get("github_reviewed_at")),
        nvd_published_at=_optional_str(advisory.get("nvd_published_at")),
        withdrawn_at=_optional_str(advisory.get("withdrawn_at")),
        vulnerabilities=_list_of_dicts(advisory.get("vulnerabilities")),
        cvss=_dict_or_empty(advisory.get("cvss")),
        cvss_severities=_dict_or_empty(advisory.get("cvss_severities")),
        cwes=_list_of_dicts(advisory.get("cwes")),
        epss=_dict_or_empty(advisory.get("epss")),
        credits=_list_of_dicts(advisory.get("credits")),
        raw=dict(advisory),
    )


def ghsa_code(value: Any) -> str | None:
    text = _optional_str(value)
    if not text:
        return None
    if not text.upper().startswith("GHSA-"):
        return None
    return text[5:]


def _cve_ids(advisory: dict[str, Any]) -> list[str]:
    candidates: list[Any] = []
    candidates.append(advisory.get("cve_id"))
    identifiers = advisory.get("identifiers")
    if isinstance(identifiers, list):
        for item in identifiers:
            if isinstance(item, dict) and str(item.get("type") or "").upper() == "CVE":
                candidates.append(item.get("value"))

    seen: set[str] = set()
    cves: list[str] = []
    for candidate in candidates:
        code = normalize_cve_code(str(candidate)) if candidate else None
        if not code:
            continue
        cve_id = f"CVE-{code}"
        if cve_id not in seen:
            cves.append(cve_id)
            seen.add(cve_id)
    return cves


def _extract_advisory(payload: Any) -> dict[str, Any] | None:
    if isinstance(payload, dict) and payload.get("ghsa_id"):
        return dict(payload)
    return None


def _list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []
    return [dict(item) for item in value if isinstance(item, dict)]


def _list_of_strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [text for item in value if (text := _optional_str(item))]


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return dict(value) if isinstance(value, dict) else {}


def _optional_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _coerce_json(data: Any) -> Any:
    if isinstance(data, str):
        return json.loads(data)
    return data
