from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from typing import Any


VULNERABILITY_ID_RE = re.compile(r"([A-Za-z]+)-(.+)")
CVE_CODE_RE = re.compile(r"^(?:CVE-)?(\d{4}-\d{4,})$", re.IGNORECASE)


@dataclass(frozen=True, slots=True)
class VulnerabilityId:
    type: str
    code: str

    @classmethod
    def parse(cls, value: str) -> "VulnerabilityId":
        match = VULNERABILITY_ID_RE.fullmatch(value.strip())
        if not match:
            raise ValueError(f"invalid vulnerability id: {value!r}")
        id_type, code = match.groups()
        id_type = id_type.upper()
        code = code.strip()
        if not id_type or not code:
            raise ValueError(f"invalid vulnerability id: {value!r}")
        return cls(type=id_type, code=code)

    @property
    def key(self) -> str:
        return f"{self.type}:{self.code}"

    @property
    def display(self) -> str:
        return f"{self.type}-{self.code}"

    def to_ref(self) -> dict[str, str]:
        return {"type": self.type, "code": self.code}


@dataclass(slots=True)
class ListEntry:
    identity: VulnerabilityId
    title: str
    vuln_type: str | None
    disclosure_date: str | None
    status: str | None
    provider: str = ""
    source_url: str | None = None
    embedded_detail: dict[str, Any] | None = None

    def to_record(
        self,
        detail: dict[str, Any] | None = None,
        *,
        detail_url: str | None = None,
    ) -> dict[str, Any]:
        provider = self.provider.strip().lower()
        effective_detail = detail if detail is not None else self.embedded_detail
        details = {provider: effective_detail} if effective_detail is not None else {}
        if provider == "cve":
            codes: list[str] = []
            cve_code = None
        elif provider == "cisco":
            codes = cve_codes(effective_detail)
            cve_code = normalize_cve_code(_detail_value(effective_detail, "cve_id"))
        else:
            codes = cve_codes(effective_detail)
            cve_code = codes[0] if codes else None

        record: dict[str, Any] = {
            "type": provider,
            "code": self.identity.code,
            "cve_code": cve_code,
            "cve_codes": codes,
            "title": self.title,
            "vuln_type": self.vuln_type,
            "disclosure_date": self.disclosure_date,
            "status": self.status,
            "details": details,
            "source": {
                "provider": provider,
                "url": self.source_url,
                "detail_url": detail_url,
            },
        }
        return record

    @property
    def key(self) -> str:
        provider = self.provider.strip().lower()
        return f"{provider}:{self.identity.code}"

    @property
    def display_id(self) -> str:
        return self.identity.display


@dataclass(slots=True)
class ListPage:
    page: int
    entries: list[ListEntry]
    total_pages: int | None = None
    total_records: int | None = None
    start_index: int | None = None
    results_per_page: int | None = None


@dataclass(slots=True)
class DetailRecord:
    cve_id: str | None = None
    danger_level: str | None = None
    exploitability: str | None = None
    patch_status: str | None = None
    description: str | None = None
    impact_range: list[str] = field(default_factory=list)
    security_versions: list[str] = field(default_factory=list)
    solution: str | None = None
    reference_links: list[str] = field(default_factory=list)
    cwe: list[dict[str, str | None]] = field(default_factory=list)
    attack_metrics: dict[str, str] = field(default_factory=dict)
    affected_software: list[dict[str, str | None]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def normalize_cve_code(value: str | None) -> str | None:
    if value is None:
        return None

    match = CVE_CODE_RE.fullmatch(str(value).strip())
    if not match:
        return None
    return match.group(1)


def primary_cve_code(detail: dict[str, Any] | None) -> str | None:
    codes = cve_codes(detail)
    return codes[0] if codes else None


def cve_codes(detail: dict[str, Any] | None) -> list[str]:
    if not isinstance(detail, dict):
        return []

    codes: list[str] = []
    seen: set[str] = set()
    for cve_id in _iter_cve_ids(detail):
        normalized = normalize_cve_code(cve_id)
        if normalized and normalized not in seen:
            seen.add(normalized)
            codes.append(normalized)
    return codes


def _iter_cve_ids(detail: dict[str, Any]) -> Iterable[str]:
    cve_id = detail.get("cve_id")
    if cve_id:
        yield str(cve_id)

    cve_code = detail.get("cveCode")
    if cve_code:
        yield str(cve_code)

    cve_id = detail.get("cveId")
    if cve_id:
        yield str(cve_id)

    cve_ids = detail.get("cve_ids")
    if isinstance(cve_ids, list):
        for item in cve_ids:
            if item:
                yield str(item)

    identifiers = detail.get("vulnerability_identifiers")
    if isinstance(identifiers, list):
        for item in identifiers:
            if isinstance(item, dict) and item.get("cve_id"):
                yield str(item["cve_id"])


def _detail_value(detail: dict[str, Any] | None, key: str) -> str | None:
    if not isinstance(detail, dict):
        return None
    value = detail.get(key)
    if value is None:
        return None
    text = str(value).strip()
    return text or None
