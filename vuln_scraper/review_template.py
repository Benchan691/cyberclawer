from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vuln_scraper.config import DEFAULT_MONGO_CONFIG_FILE, mongo_collection_for_provider
from vuln_scraper.scrapers import get_provider, provider_keys
from vuln_scraper.severity import normalize_severity


_CISCO_PARAGRAPH_TAG_RE = re.compile(r"</?p(?:\s[^>]*)?>", re.IGNORECASE)
_CVE_CODE_RE = re.compile(r"^(?:CVE-)?(\d{4}-\d{4,})$", re.IGNORECASE)
_URL_RE = re.compile(r"https?://[^\s<>\"]+")


REVIEW_TEMPLATE_FIELDS = (
    "title",
    "description",
    "impacts",
    "affected",
    "cve",
    "recommendation",
    "related_link",
)

_REVIEW_ARRAY_FIELDS = {"affected", "related_link"}


def review_template_from_document(document: dict[str, Any]) -> dict[str, Any]:
    provider = _text(document.get("type")).lower()
    if not provider:
        provider = _text(document.get("_id")).partition(":")[0].lower()
    detail = _detail(document, provider)
    mapper = _MAPPERS.get(provider, _generic)
    mapped = mapper(document, detail)
    title = _text(mapped.get("title") or document.get("title"))
    raw_impacts = _string(document.get("severity") or mapped.get("impacts"))
    impacts = normalize_severity(raw_impacts) if raw_impacts else ""
    return {
        "title": title,
        "description": _string(mapped.get("description")),
        "impacts": impacts,
        "affected": _string_array(mapped.get("affected")),
        "cve": _string(mapped.get("cve")),
        "recommendation": _string(mapped.get("recommendation")),
        "related_link": _string_array(mapped.get("related_link")),
    }


def _avd(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    affected = _join_dicts(
        detail.get("affected_software"),
        lambda item: _parts(
            item.get("vendor"),
            item.get("product"),
            item.get("version"),
        ),
    )
    return _base(
        document,
        description=detail.get("description"),
        impacts=detail.get("danger_level"),
        affected=affected,
        cve=_document_cve(document),
        recommendation=detail.get("solution"),
        related_link=_join(detail.get("reference_links")),
    )


def _hkcert(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    products = detail.get("vulnerable_products") or detail.get("table")
    affected = _join_dicts(
        products,
        lambda item: _parts(
            item.get("name") or item.get("vulnerable_product"),
            item.get("details"),
        ),
    )
    affected = affected or _join(detail.get("systems_affected"))
    return _base(
        document,
        description=detail.get("summary") or detail.get("intro"),
        impacts=detail.get("risk_level") or _first_nested(products, "risk_level"),
        affected=affected,
        cve=(
            _document_cve(document)
            or _join(_nested_values(detail.get("vulnerability_identifiers"), "cve_id"))
        ),
        recommendation=detail.get("solutions"),
        related_link=_join(detail.get("related_links")),
    )


def _cve(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    severity = _first_available(
        detail,
        (
            ("metrics", "cvss_v40", "cvssData", "baseSeverity"),
            ("metrics", "cvss_v31", "cvssData", "baseSeverity"),
            ("metrics", "cvss_v30", "cvssData", "baseSeverity"),
            ("metrics", "cvss_v2", "baseSeverity"),
        ),
    )
    return _base(
        document,
        description=_join(_nested_values(detail.get("descriptions"), "value")),
        impacts=severity,
        affected=_cve_affected(detail),
        cve=_document_cve(document),
        related_link=_join(_nested_values(detail.get("references"), "url")),
    )


def _cisco(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    return _base(
        document,
        description=_strip_cisco_paragraph_tags(detail.get("summary")),
        impacts=detail.get("sir") or detail.get("cvss_base_score"),
        affected=_join(detail.get("product_names")),
        cve=_document_cve(document),
        related_link=_join([detail.get("publication_url"), detail.get("cvrf_url"), detail.get("csaf_url")]),
    )


def _github_advisory(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    vulnerabilities = _dicts(detail.get("vulnerabilities"))
    affected = _join(
        _parts(
            f"{_text(_path(item, 'package', 'ecosystem'))}:{_text(_path(item, 'package', 'name'))}",
            item.get("vulnerable_version_range"),
        )
        for item in vulnerabilities
    )
    patched = _join(item.get("first_patched_version") for item in vulnerabilities)
    return _base(
        document,
        description=detail.get("description") or detail.get("summary"),
        impacts=detail.get("severity"),
        affected=affected,
        cve=_document_cve(document),
        recommendation=patched,
        related_link=_join(detail.get("references")),
    )


def _zeroday(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    return _base(
        document,
        description=detail.get("description"),
        impacts="",
        affected=detail.get("vulnerable_component"),
        cve=_document_cve(document),
        recommendation=detail.get("patch_status"),
        related_link=_join(detail.get("reference_links")),
    )


def _govcert(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    return _base(
        document,
        description=detail.get("description"),
        impacts="",
        affected=_join(detail.get("affected_systems")),
        cve=_document_cve(document),
        recommendation=detail.get("recommendation"),
        related_link=_join(detail.get("more_information_links")),
    )


def _infosec(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    mapped = _govcert(document, detail)
    mapped["description"] = detail.get("description") or detail.get("summary")
    return mapped


def _huawei_sa(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    raw = detail.get("raw") if isinstance(detail.get("raw"), dict) else {}
    vul = detail.get("vul") or raw.get("vul")
    return _base(
        document,
        description=detail.get("summary") or raw.get("summary"),
        impacts=detail.get("severity") or raw.get("severity"),
        affected="",
        cve=_document_cve(document)
        or _first(detail.get("cve_ids"))
        or _first_nested(vul, "cveId"),
        related_link=detail.get("allPath") if isinstance(detail.get("allPath"), str) else raw.get("allPath"),
    )


def _paloalto(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    status_lines: list[str] = []
    for item in _dicts(detail.get("product_status")):
        affected = item.get("affected")
        if affected:
            status_lines.append(_string(affected))
    affected = _join([_join(detail.get("products")), _join(status_lines)])
    return _base(
        document,
        description=detail.get("description"),
        impacts=detail.get("severity"),
        affected=affected,
        cve=_document_cve(document),
        recommendation=_join([detail.get("solution"), detail.get("workarounds")]),
        related_link=_join(detail.get("reference_links")),
    )


def _qianxin(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    description = detail.get("description")
    if not isinstance(description, dict):
        description = {}
    vulnerability = description.get("vulnerability_information")
    if not isinstance(vulnerability, dict):
        vulnerability = {}
    assessment = description.get("threat_assessment")
    if not isinstance(assessment, dict):
        assessment = {}
    risk = vulnerability.get("risk")
    if not isinstance(risk, dict):
        risk = {}
    other_components = vulnerability.get("other_affected_components")
    if _text(other_components) == "无":
        other_components = ""
    return _base(
        document,
        description=_join(
            [
                description.get("security_advisory"),
                vulnerability.get("summary"),
                vulnerability.get("vulnerability_description"),
                assessment.get("impact_description"),
                description.get("affected_assets"),
            ]
        )
        or detail.get("description"),
        impacts=detail.get("level")
        or assessment.get("cvss_3_1_rating")
        or risk.get("qianxin_cert_rating")
        or risk.get("risk_level"),
        affected=_join(
            [
                _parts(vulnerability.get("vendor"), vulnerability.get("product")),
                vulnerability.get("affected_versions"),
                other_components,
            ]
        ),
        cve=_document_cve(document)
        or vulnerability.get("cve_id")
        or assessment.get("cve_id")
        or _first(detail.get("cve_ids")),
        recommendation=_join(description.get("recommendations")),
        related_link=_join(detail.get("reference_links")),
    )


def _ransomwarelive(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    return _base(
        document,
        description=detail.get("press"),
        impacts="",
        affected="",
        cve=_document_cve(document),
        related_link=_join([detail.get("website"), detail.get("permalink"), detail.get("screenshot")]),
    )


def _format_description_table(table: dict[str, Any]) -> str:
    headers = [_text(header) for header in (table.get("headers") or []) if _text(header)]
    rows = _dicts(table.get("rows"))
    if not headers and not rows:
        return ""
    lines: list[str] = []
    if headers:
        lines.append(" | ".join(headers))
    for row in rows:
        cells = [_text(row.get(header)) for header in headers]
        if any(cells):
            lines.append(" | ".join(cells))
    return "\n".join(lines)


def _format_description_tables(tables: Any) -> str:
    return "\n\n".join(
        text for table in _dicts(tables) if (text := _format_description_table(table))
    )


def _splunk_description(detail: dict[str, Any]) -> str:
    text = _text(detail.get("description") or "")
    table_text = _format_description_tables(detail.get("description_tables"))
    if table_text and text:
        return f"{text}\n\n{table_text}"
    return table_text or text


def _splunk(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    status_versions = _join_dicts(
        detail.get("product_status"),
        lambda item: _parts(item.get("product"), item.get("base_version"), item.get("affected_version")),
    )
    affected = _join(
        [
            detail.get("affected_products"),
            detail.get("affected_versions"),
            detail.get("all_affected_versions"),
            detail.get("affected_components"),
            status_versions,
        ]
    )
    return _base(
        document,
        description=_splunk_description(detail),
        impacts=detail.get("severity") or detail.get("severity_summary") or detail.get("severity_detail"),
        affected=_string(affected),
        cve=_document_cve(document),
        recommendation=_join([detail.get("solution"), detail.get("mitigations")]),
        related_link=_join(detail.get("reference_links")),
    )


def _hikvision(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    return _base(
        document,
        description=detail.get("summary") or detail.get("description"),
        impacts=detail.get("severity"),
        affected=_join(detail.get("affected_products")),
        cve=_document_cve(document),
        recommendation=detail.get("solution"),
        related_link=_join(detail.get("reference_links")),
    )


def _cnnvd(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    return _base(
        document,
        description=detail.get("vulDesc") or detail.get("productDesc"),
        impacts=detail.get("hazardLevel"),
        affected=_join([detail.get("affectedProduct"), detail.get("affectedVendor")]),
        cve=_document_cve(document),
        recommendation=detail.get("patch"),
        related_link=_extract_urls(detail.get("referUrl")),
    )


def _cnvd(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    return _base(
        document,
        description=detail.get("description"),
        impacts=document.get("status") or detail.get("severity"),
        affected=_join(detail.get("affected_products")),
        cve=_document_cve(document),
        recommendation=detail.get("solution"),
        related_link=_join(detail.get("reference_links")),
    )


def _juniper(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    return _base(
        document,
        description=detail.get("description") or detail.get("summary"),
        impacts=_path(detail, "raw_fields", "severity"),
        affected=_join(detail.get("products")),
        cve=_document_cve(document),
        recommendation=_join([detail.get("solution"), detail.get("workaround")]),
        related_link=_join(detail.get("reference_links")),
    )


def _generic(document: dict[str, Any], detail: dict[str, Any]) -> dict[str, Any]:
    return _base(
        document,
        description=detail.get("description") or detail.get("summary"),
        impacts="",
        cve=_document_cve(document),
    )


def _cve_affected(detail: dict[str, Any]) -> str:
    affected = _join_dicts(
        detail.get("affected"),
        lambda item: _parts(item.get("vendor"), item.get("product")),
    )
    if affected:
        return affected
    legacy = _join(detail.get("affected_products"))
    if legacy:
        return legacy
    configurations = detail.get("configurations")
    lines: list[str] = []
    for configuration in _dicts(configurations):
        for node in _dicts(configuration.get("nodes")):
            for match in _dicts(node.get("cpeMatch")):
                if match.get("vulnerable") is False:
                    continue
                line = _parts(
                    match.get("criteria"),
                    _version_bound(match, "versionStartIncluding", ">="),
                    _version_bound(match, "versionStartExcluding", ">"),
                    _version_bound(match, "versionEndIncluding", "<="),
                    _version_bound(match, "versionEndExcluding", "<"),
                )
                if line:
                    lines.append(line)
    return _join(lines)


def _version_bound(item: dict[str, Any], key: str, operator: str) -> str:
    value = _text(item.get(key))
    return f"{operator}{value}" if value else ""


def _strip_cisco_paragraph_tags(value: Any) -> Any:
    if not isinstance(value, str):
        return value
    return _CISCO_PARAGRAPH_TAG_RE.sub("", value)


def _base(document: dict[str, Any], **values: Any) -> dict[str, Any]:
    return {"title": document.get("title"), **values}


def _detail(document: dict[str, Any], provider: str) -> dict[str, Any]:
    details = document.get("details")
    if not isinstance(details, dict):
        return {}
    value = details.get(provider)
    if isinstance(value, dict):
        return value
    return details


def _document_cve(document: dict[str, Any]) -> str:
    if _text(document.get("_id")).startswith("cve:"):
        code = _text(document.get("code"))
        return f"CVE-{code}" if code and not code.upper().startswith("CVE-") else code
    return _join(_prefixed_cve_codes(document.get("cve_ids")))


def _string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, (list, tuple, set)):
        return _join(value)
    if isinstance(value, dict):
        return _json(value)
    return str(value).strip()


def _extract_urls(value: Any) -> list[str]:
    links: list[str] = []
    for text in _string_array(value):
        for match in _URL_RE.findall(text):
            url = match.rstrip(").,;，。")
            if url and url not in links:
                links.append(url)
    return links


def _string_array(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [line.strip() for line in value.splitlines() if line.strip()]
    if isinstance(value, (list, tuple, set)):
        lines: list[str] = []
        for item in value:
            lines.extend(_string_array(item))
        return lines
    text = _string(value)
    return [text] if text else []


def _join(values: Any) -> str:
    if values is None:
        return ""
    if isinstance(values, str):
        return values.strip()
    if isinstance(values, dict):
        values = [values]
    try:
        items = list(values)
    except TypeError:
        items = [values]
    return "\n".join(text for item in items if (text := _string(item)))


def _join_dicts(values: Any, formatter: Callable[[dict[str, Any]], str]) -> str:
    return _join(formatter(item) for item in _dicts(values))


def _prefixed_cve_code(value: Any) -> str:
    text = _string(value)
    match = _CVE_CODE_RE.fullmatch(text)
    return f"CVE-{match.group(1).upper()}" if match else text


def _prefixed_cve_codes(values: Any) -> list[str]:
    codes: list[str] = []
    seen: set[str] = set()
    for value in _string_array(values):
        code = _prefixed_cve_code(value)
        if code and code not in seen:
            seen.add(code)
            codes.append(code)
    return codes


def _dicts(values: Any) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    return [item for item in values if isinstance(item, dict)]


def _json(value: Any) -> str:
    if value in (None, "", [], {}):
        return ""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), default=str)


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else _string(value)


def _parts(*values: Any) -> str:
    return " ".join(text for value in values if (text := _text(value)))


def _first(values: Any) -> Any:
    if isinstance(values, list):
        return next((value for value in values if _string(value)), "")
    return values if _string(values) else ""


def _first_nested(values: Any, *path: str) -> Any:
    return _first(_nested_values(values, *path))


def _nested_values(values: Any, *path: str) -> list[Any]:
    results: list[Any] = []
    nodes = values if isinstance(values, list) else [values]
    for node in nodes:
        value = _path(node, *path)
        if isinstance(value, list):
            results.extend(value)
        elif value is not None:
            results.append(value)
    return results


def _path(value: Any, *parts: str) -> Any:
    nodes = [value]
    for part in parts:
        next_nodes: list[Any] = []
        for node in nodes:
            if isinstance(node, dict) and part in node:
                child = node[part]
                next_nodes.extend(child if isinstance(child, list) else [child])
        nodes = next_nodes
        if not nodes:
            return None
    return nodes[0] if len(nodes) == 1 else nodes


def _first_available(detail: dict[str, Any], paths: tuple[tuple[str, ...], ...]) -> Any:
    for path in paths:
        value = _path(detail, *path)
        first = _first(value)
        if _string(first):
            return first
    return ""


_MAPPERS: dict[str, Callable[[dict[str, Any], dict[str, Any]], dict[str, Any]]] = {
    "avd": _avd,
    "hkcert": _hkcert,
    "cve": _cve,
    "cisco": _cisco,
    "github_advisory": _github_advisory,
    "zeroday": _zeroday,
    "govcert": _govcert,
    "infosec": _infosec,
    "huawei_sa": _huawei_sa,
    "paloalto": _paloalto,
    "qianxin": _qianxin,
    "ransomwarelive": _ransomwarelive,
    "splunk": _splunk,
    "hikvision": _hikvision,
    "cnnvd": _cnnvd,
    "cnvd": _cnvd,
    "juniper": _juniper,
}


class ReviewViewError(RuntimeError):
    """Raised when a review view cannot be refreshed safely."""


def review_view_name(collection_name: str) -> str:
    return f"{collection_name}_review"


def ensure_review_view(database: Any, *, provider: str, collection_name: str) -> bool:
    existing = {
        item["name"]: item.get("type")
        for item in database.list_collections(filter={})
    }
    if collection_name not in existing:
        return False

    view_name = review_view_name(collection_name)
    view_type = existing.get(view_name)
    if view_type and view_type != "view":
        raise ReviewViewError(
            f"refusing to replace physical collection {view_name!r} with a review view"
        )
    if view_type == "view":
        database[view_name].drop()

    database.command(
        {
            "create": view_name,
            "viewOn": collection_name,
            "pipeline": review_view_pipeline(provider),
        }
    )
    _validate_review_view(database, view_name)
    return True


def _validate_review_view(database: Any, view_name: str, *, sample_size: int = 100) -> None:
    for index, document in enumerate(database[view_name].find({}).limit(sample_size), start=1):
        errors = _review_document_errors(document)
        if errors:
            raise ReviewViewError(
                f"review view {view_name!r} has invalid document {index}: {', '.join(errors)}"
            )


def _review_document_errors(document: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    fields = tuple(document)
    if fields != REVIEW_TEMPLATE_FIELDS:
        missing = [field for field in REVIEW_TEMPLATE_FIELDS if field not in document]
        extra = [field for field in document if field not in REVIEW_TEMPLATE_FIELDS]
        if missing:
            errors.append(f"missing fields {missing!r}")
        if extra:
            errors.append(f"extra fields {extra!r}")

    for field in REVIEW_TEMPLATE_FIELDS:
        value = document.get(field)
        if field in _REVIEW_ARRAY_FIELDS:
            if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
                errors.append(f"{field} must be an array of strings")
        elif not isinstance(value, str):
            errors.append(f"{field} must be a string")
    return errors


@dataclass(slots=True)
class ReviewViewRefreshResult:
    provider: str
    collection_name: str
    view_name: str
    refreshed: bool
    message: str = ""


def refresh_review_views(
    database: Any,
    *,
    providers: list[str] | None = None,
    mongo_config_file: Path | str | None = DEFAULT_MONGO_CONFIG_FILE,
) -> list[ReviewViewRefreshResult]:
    keys = list(providers) if providers else list(provider_keys())
    results: list[ReviewViewRefreshResult] = []
    for key in keys:
        provider = get_provider(key)
        collection_name = mongo_collection_for_provider(
            key,
            mongo_config_file,
            default=provider.default_mongo_collection,
        )
        view_name = review_view_name(collection_name)
        try:
            refreshed = ensure_review_view(
                database,
                provider=key,
                collection_name=collection_name,
            )
        except ReviewViewError as exc:
            results.append(
                ReviewViewRefreshResult(
                    provider=key,
                    collection_name=collection_name,
                    view_name=view_name,
                    refreshed=False,
                    message=str(exc),
                )
            )
            continue
        message = "refreshed" if refreshed else "source collection missing"
        results.append(
            ReviewViewRefreshResult(
                provider=key,
                collection_name=collection_name,
                view_name=view_name,
                refreshed=refreshed,
                message=message,
            )
        )
    return results


def review_view_pipeline(provider: str) -> list[dict[str, Any]]:
    detail = "$details"
    fields = {
        "title": _mstr("$title"),
        "description": _mongo_description(provider, detail),
        "impacts": _mongo_impacts(provider, detail),
        "affected": _marray_lines(_mongo_affected(provider, detail)),
        "cve": _mongo_cve(provider, detail),
        "recommendation": _mongo_recommendation(provider, detail),
        "related_link": _marray_lines(_mongo_related_link(provider, detail)),
    }
    return [{"$project": {"_id": 0, **fields}}]


def _mongo_description(provider: str, detail: str) -> dict[str, Any]:
    sources: dict[str, list[Any]] = {
        "avd": [f"{detail}.description"],
        "hkcert": [f"{detail}.summary", f"{detail}.intro"],
        "cve": [_mjoin_values(f"{detail}.descriptions", "value")],
        "cisco": [_mstrip_cisco_paragraph_tags(f"{detail}.summary")],
        "github_advisory": [f"{detail}.description", f"{detail}.summary"],
        "zeroday": [f"{detail}.description"],
        "govcert": [f"{detail}.description"],
        "infosec": [f"{detail}.description", f"{detail}.summary"],
        "huawei_sa": [f"{detail}.summary", f"{detail}.raw.summary"],
        "paloalto": [f"{detail}.description"],
        "qianxin": [
            _mjoin_many(
                [
                    f"{detail}.description.security_advisory",
                    f"{detail}.description.vulnerability_information.summary",
                    f"{detail}.description.vulnerability_information.vulnerability_description",
                    f"{detail}.description.threat_assessment.impact_description",
                    f"{detail}.description.affected_assets",
                    f"{detail}.description",
                ]
            )
        ],
        "ransomwarelive": [f"{detail}.press"],
        "splunk": [_mongo_splunk_description(detail)],
        "hikvision": [f"{detail}.summary", f"{detail}.description"],
        "cnnvd": [f"{detail}.vulDesc", f"{detail}.productDesc"],
        "cnvd": [f"{detail}.description"],
        "juniper": [f"{detail}.description", f"{detail}.summary"],
    }
    return _mfirst(sources.get(provider, []))


def _mongo_impacts(provider: str, detail: str) -> dict[str, Any]:
    return _mstr("$severity")


def _mnormalize_severity(value_expr: Any) -> dict[str, Any]:
    text = {"$trim": {"input": _mstr(value_expr)}}
    lower = {"$toLower": text}
    return {
        "$switch": {
            "branches": [
                {"case": {"$in": [text, ["1", "超危", "严重"]]}, "then": "Critical"},
                {"case": {"$in": [lower, ["critical", "crit"]]}, "then": "Critical"},
                {"case": {"$in": [text, ["2", "高危", "高"]]}, "then": "High"},
                {"case": {"$regexMatch": {"input": lower, "regex": "^high"}}, "then": "High"},
                {"case": {"$in": [text, ["3", "中危", "中"]]}, "then": "Medium"},
                {"case": {"$in": [lower, ["medium", "moderate", "med"]]}, "then": "Medium"},
                {"case": {"$regexMatch": {"input": lower, "regex": "^medium|^moderate"}}, "then": "Medium"},
                {"case": {"$in": [text, ["4", "低危", "低"]]}, "then": "Low"},
                {"case": {"$in": [lower, ["low", "informational", "info", "none"]]}, "then": "Low"},
                {"case": {"$regexMatch": {"input": lower, "regex": "^low"}}, "then": "Low"},
            ],
            "default": {
                "$cond": [
                    {"$eq": [text, ""]},
                    "",
                    "Unknown",
                ]
            },
        }
    }


def _mongo_affected(provider: str, detail: str) -> dict[str, Any]:
    if provider == "avd":
        return _mjoin_mapped(
            f"{detail}.affected_software",
            _mconcat_parts(["$$item.vendor", "$$item.product", "$$item.version"]),
        )
    if provider == "hkcert":
        products = _mjoin_mapped(
            _mfirst_array([f"{detail}.vulnerable_products", f"{detail}.table"]),
            _mconcat_parts(
                [
                    _mfirst(["$$item.name", "$$item.vulnerable_product"]),
                    "$$item.details",
                ]
            ),
        )
        return _mfirst([products, _mjoin(f"{detail}.systems_affected")])
    if provider == "cve":
        return _mfirst(
            [
                _mjoin_mapped(
                    f"{detail}.affected",
                    _mconcat_parts(["$$item.vendor", "$$item.product"]),
                ),
                _mjoin(f"{detail}.affected_products"),
                _mongo_cve_affected(f"{detail}.configurations"),
            ]
        )
    if provider == "cisco":
        return _mjoin(f"{detail}.product_names")
    if provider == "github_advisory":
        return _mjoin_mapped(
            f"{detail}.vulnerabilities",
            _mconcat_parts(
                [
                    {
                        "$concat": [
                            _mstr("$$item.package.ecosystem"),
                            ":",
                            _mstr("$$item.package.name"),
                        ]
                    },
                    "$$item.vulnerable_version_range",
                ]
            ),
        )
    if provider == "zeroday":
        return _mstr(f"{detail}.vulnerable_component")
    if provider in {"govcert", "infosec"}:
        return _mjoin(f"{detail}.affected_systems")
    if provider == "paloalto":
        return _mjoin_many(
            [
                _mjoin(f"{detail}.products"),
                _mjoin_mapped(
                    f"{detail}.product_status",
                    _mconcat_parts(["$$item.product", "$$item.affected"]),
                ),
            ]
        )
    if provider == "qianxin":
        return _mjoin_many(
            [
                _mconcat_parts(
                    [
                        f"{detail}.description.vulnerability_information.vendor",
                        f"{detail}.description.vulnerability_information.product",
                    ]
                ),
                _mjoin(f"{detail}.description.vulnerability_information.affected_versions"),
                {
                    "$cond": [
                        {
                            "$eq": [
                                _mstr(
                                    f"{detail}.description.vulnerability_information.other_affected_components"
                                ),
                                "无",
                            ]
                        },
                        "",
                        f"{detail}.description.vulnerability_information.other_affected_components",
                    ]
                },
            ]
        )
    if provider == "splunk":
        return _mjoin_many(
            [
                f"{detail}.affected_products",
                f"{detail}.affected_versions",
                f"{detail}.all_affected_versions",
                f"{detail}.affected_components",
                _mjoin_mapped(
                    f"{detail}.product_status",
                    _mconcat_parts(
                        ["$$item.product", "$$item.base_version", "$$item.affected_version"]
                    ),
                ),
            ]
        )
    if provider == "hikvision":
        return _mjoin(f"{detail}.affected_products")
    if provider == "cnnvd":
        return _mjoin_many([f"{detail}.affectedProduct", f"{detail}.affectedVendor"])
    if provider == "cnvd":
        return _mjoin(f"{detail}.affected_products")
    if provider == "juniper":
        return _mjoin(f"{detail}.products")
    return _mstr("")


def _mongo_cve(provider: str, detail: str) -> dict[str, Any]:
    if provider == "cve":
        return {
            "$concat": [
                "CVE-",
                {
                    "$replaceAll": {
                        "input": _mstr("$code"),
                        "find": "CVE-",
                        "replacement": "",
                    }
                },
            ]
        }
    return _mjoin("$cve_ids")


def _mongo_recommendation(provider: str, detail: str) -> dict[str, Any]:
    sources: dict[str, list[Any]] = {
        "avd": [f"{detail}.solution"],
        "hkcert": [f"{detail}.solutions"],
        "github_advisory": [
            _mjoin_mapped(f"{detail}.vulnerabilities", _mstr("$$item.first_patched_version"))
        ],
        "zeroday": [f"{detail}.patch_status"],
        "govcert": [f"{detail}.recommendation"],
        "infosec": [f"{detail}.recommendation"],
        "paloalto": [_mjoin_many([f"{detail}.solution", f"{detail}.workarounds"])],
        "qianxin": [_mjoin(f"{detail}.description.recommendations")],
        "splunk": [_mjoin_many([f"{detail}.solution", f"{detail}.mitigations"])],
        "hikvision": [f"{detail}.solution"],
        "cnnvd": [f"{detail}.patch"],
        "cnvd": [f"{detail}.solution"],
        "juniper": [_mjoin_many([f"{detail}.solution", f"{detail}.workaround"])],
    }
    return _mfirst(sources.get(provider, []))


def _mongo_related_link(provider: str, detail: str) -> dict[str, Any]:
    if provider == "cnnvd":
        return _mjoin(_mextract_urls(f"{detail}.referUrl"))
    if provider == "cve":
        return _mjoin_values(f"{detail}.references", "url")
    if provider == "cisco":
        return _mjoin_many(
            [f"{detail}.publication_url", f"{detail}.cvrf_url", f"{detail}.csaf_url"]
        )
    if provider == "ransomwarelive":
        return _mjoin_many(
            [f"{detail}.website", f"{detail}.permalink", f"{detail}.screenshot"]
        )
    if provider == "huawei_sa":
        return _mfirst([f"{detail}.allPath", f"{detail}.raw.allPath"])

    sources: dict[str, list[Any]] = {
        "avd": [f"{detail}.reference_links"],
        "hkcert": [f"{detail}.related_links"],
        "github_advisory": [f"{detail}.references"],
        "zeroday": [f"{detail}.reference_links"],
        "govcert": [f"{detail}.more_information_links"],
        "infosec": [f"{detail}.more_information_links"],
        "paloalto": [f"{detail}.reference_links"],
        "qianxin": [f"{detail}.reference_links"],
        "splunk": [f"{detail}.reference_links"],
        "hikvision": [f"{detail}.reference_links"],
        "cnvd": [f"{detail}.reference_links"],
        "juniper": [f"{detail}.reference_links"],
    }
    values = sources.get(provider, [])
    return _mjoin(values[0]) if values else _mstr("")


def _mstr(value: Any) -> dict[str, Any]:
    return {"$convert": {"input": value, "to": "string", "onError": "", "onNull": ""}}


def _mstrip_cisco_paragraph_tags(value: Any) -> dict[str, Any]:
    result: Any = _mstr(value)
    for tag in ("<p>", "</p>", "<P>", "</P>"):
        result = {
            "$replaceAll": {
                "input": result,
                "find": tag,
                "replacement": "",
            }
        }
    return result


def _marray_lines(value: Any) -> dict[str, Any]:
    return {
        "$filter": {
            "input": {"$split": [_mstr(value), "\n"]},
            "as": "line",
            "cond": {"$ne": [{"$trim": {"input": "$$line"}}, ""]},
        }
    }


def _mfirst(values: list[Any]) -> dict[str, Any]:
    converted = [_mstr(value) for value in values]
    return {
        "$let": {
            "vars": {"values": converted},
            "in": {
                "$ifNull": [
                    {
                        "$arrayElemAt": [
                            {
                                "$filter": {
                                    "input": "$$values",
                                    "as": "value",
                                    "cond": {"$ne": [{"$trim": {"input": "$$value"}}, ""]},
                                }
                            },
                            0,
                        ]
                    },
                    "",
                ]
            },
        }
    }


def _mfirst_array(values: list[Any]) -> dict[str, Any]:
    return {
        "$let": {
            "vars": {"arrays": values},
            "in": {
                "$ifNull": [
                    {
                        "$arrayElemAt": [
                            {
                                "$filter": {
                                    "input": "$$arrays",
                                    "as": "value",
                                    "cond": {"$isArray": "$$value"},
                                }
                            },
                            0,
                        ]
                    },
                    [],
                ]
            },
        }
    }


def _mfirst_item(value: Any) -> dict[str, Any]:
    return _mstr(
        {
            "$arrayElemAt": [
                {"$cond": [{"$isArray": value}, value, []]},
                0,
            ]
        }
    )


def _mjoin(value: Any) -> dict[str, Any]:
    return _mjoin_mapped(value, _mstr("$$item"))


def _mprefixed_cve_code(value: Any) -> dict[str, Any]:
    text = _mstr(value)
    trimmed = {"$trim": {"input": text}}
    upper = {"$toUpper": trimmed}
    return {
        "$cond": [
            {"$eq": [trimmed, ""]},
            "",
            {
                "$cond": [
                    {"$regexMatch": {"input": upper, "regex": "^CVE-"}},
                    upper,
                    {"$concat": ["CVE-", upper]},
                ]
            },
        ]
    }


def _mprefixed_cve_codes(value: Any) -> dict[str, Any]:
    return _mjoin_mapped(value, _mprefixed_cve_code("$$item"))


def _mextract_urls(value: Any) -> dict[str, Any]:
    return {
        "$let": {
            "vars": {
                "matches": {
                    "$regexFindAll": {
                        "input": _mstr(value),
                        "regex": r"https?://[^\s<>\"]+",
                    }
                }
            },
            "in": {
                "$map": {
                    "input": {"$ifNull": ["$$matches", []]},
                    "as": "match",
                    "in": "$$match.match",
                }
            },
        }
    }


def _mreduce_concat_non_empty(items: Any, *, separator: str) -> dict[str, Any]:
    return {
        "$reduce": {
            "input": {
                "$filter": {
                    "input": {"$cond": [{"$isArray": items}, items, []]},
                    "as": "part",
                    "cond": {"$ne": [{"$trim": {"input": {"$toString": "$$part"}}}, ""]},
                }
            },
            "initialValue": "",
            "in": {
                "$concat": [
                    "$$value",
                    {"$cond": [{"$eq": ["$$value", ""]}, "", separator]},
                    {"$toString": "$$this"},
                ]
            },
        }
    }


def _mongo_splunk_row_line(headers: Any, row: Any) -> dict[str, Any]:
    # Views disallow $getField with a dynamic field name; match via $objectToArray instead.
    return _mreduce_concat_non_empty(
        {
            "$map": {
                "input": {"$cond": [{"$isArray": headers}, headers, []]},
                "as": "header",
                "in": {
                    "$let": {
                        "vars": {
                            "match": {
                                "$first": {
                                    "$filter": {
                                        "input": {
                                            "$cond": [
                                                {"$eq": [{"$type": row}, "object"]},
                                                {"$objectToArray": row},
                                                [],
                                            ]
                                        },
                                        "as": "entry",
                                        "cond": {"$eq": ["$$entry.k", "$$header"]},
                                    }
                                }
                            }
                        },
                        "in": {"$toString": {"$ifNull": ["$$match.v", ""]}},
                    }
                },
            }
        },
        separator=" | ",
    )


def _mongo_splunk_description(detail: str) -> dict[str, Any]:
    tables_field = f"{detail}.description_tables"
    desc_field = f"{detail}.description"

    table_strings = {
        "$map": {
            "input": {"$cond": [{"$isArray": tables_field}, tables_field, []]},
            "as": "table",
            "in": {
                "$let": {
                    "vars": {
                        "header_line": _mreduce_concat_non_empty(
                            {"$ifNull": ["$$table.headers", []]},
                            separator=" | ",
                        ),
                        "row_lines": {
                            "$map": {
                                "input": {"$ifNull": ["$$table.rows", []]},
                                "as": "row",
                                "in": _mongo_splunk_row_line(
                                    {"$ifNull": ["$$table.headers", []]},
                                    "$$row",
                                ),
                            }
                        },
                    },
                    "in": {
                        "$let": {
                            "vars": {
                                "body": _mreduce_join("$$row_lines", separator="\n"),
                            },
                            "in": {
                                "$cond": [
                                    {
                                        "$and": [
                                            {"$ne": [{"$trim": {"input": "$$header_line"}}, ""]},
                                            {"$ne": [{"$trim": {"input": "$$body"}}, ""]},
                                        ]
                                    },
                                    {"$concat": ["$$header_line", "\n", "$$body"]},
                                    {
                                        "$cond": [
                                            {"$ne": [{"$trim": {"input": "$$header_line"}}, ""]},
                                            "$$header_line",
                                            "$$body",
                                        ]
                                    },
                                ]
                            },
                        }
                    },
                }
            },
        }
    }
    tables_text = _mreduce_join(
        {
            "$filter": {
                "input": table_strings,
                "as": "table_text",
                "cond": {"$ne": [{"$trim": {"input": "$$table_text"}}, ""]},
            }
        },
        separator="\n\n",
    )
    return {
        "$let": {
            "vars": {
                "text": _mstr(desc_field),
                "tables": tables_text,
            },
            "in": {
                "$cond": [
                    {
                        "$and": [
                            {"$ne": [{"$trim": {"input": "$$text"}}, ""]},
                            {"$ne": [{"$trim": {"input": "$$tables"}}, ""]},
                        ]
                    },
                    {"$concat": ["$$text", "\n\n", "$$tables"]},
                    {
                        "$cond": [
                            {"$ne": [{"$trim": {"input": "$$tables"}}, ""]},
                            "$$tables",
                            "$$text",
                        ]
                    },
                ]
            },
        }
    }


def _mreduce_join(items: Any, *, separator: str = "\n") -> dict[str, Any]:
    return {
        "$let": {
            "vars": {
                "lines": {
                    "$filter": {
                        "input": {"$ifNull": [items, []]},
                        "as": "line",
                        "cond": {"$ne": [{"$trim": {"input": {"$toString": "$$line"}}}, ""]},
                    }
                }
            },
            "in": {
                "$reduce": {
                    "input": "$$lines",
                    "initialValue": "",
                    "in": {
                        "$concat": [
                            "$$value",
                            {"$cond": [{"$eq": ["$$value", ""]}, "", separator]},
                            {"$toString": "$$this"},
                        ]
                    },
                }
            },
        }
    }


def _mjoin_many(values: list[Any]) -> dict[str, Any]:
    return _mjoin_mapped(
        {"$concatArrays": [[value] for value in values]},
        _mstr("$$item"),
    )


def _mjoin_values(value: Any, field: str) -> dict[str, Any]:
    return _mjoin_mapped(value, _mstr(f"$$item.{field}"))


def _mjoin_mapped(
    value: Any,
    mapped_expression: Any,
    *,
    separator: str = "\n",
) -> dict[str, Any]:
    return {
        "$let": {
            "vars": {
                "lines": {
                    "$filter": {
                        "input": {
                            "$map": {
                                "input": {"$cond": [{"$isArray": value}, value, []]},
                                "as": "item",
                                "in": mapped_expression,
                            }
                        },
                        "as": "line",
                        "cond": {"$ne": [{"$trim": {"input": "$$line"}}, ""]},
                    }
                }
            },
            "in": {
                "$reduce": {
                    "input": "$$lines",
                    "initialValue": "",
                    "in": {
                        "$concat": [
                            "$$value",
                            {"$cond": [{"$eq": ["$$value", ""]}, "", separator]},
                            "$$this",
                        ]
                    },
                }
            },
        }
    }


def _mconcat_parts(values: list[Any]) -> dict[str, Any]:
    return {
        "$let": {
            "vars": {"parts": [_mstr(value) for value in values]},
            "in": {
                "$reduce": {
                    "input": {
                        "$filter": {
                            "input": "$$parts",
                            "as": "part",
                            "cond": {"$ne": [{"$trim": {"input": "$$part"}}, ""]},
                        }
                    },
                    "initialValue": "",
                    "in": {
                        "$concat": [
                            "$$value",
                            {"$cond": [{"$eq": ["$$value", ""]}, "", " "]},
                            "$$this",
                        ]
                    },
                }
            },
        }
    }


def _mfirst_array_value(value: Any, field: str) -> dict[str, Any]:
    return _mfirst_nested(value, field)


def _mfirst_nested(value: Any, field: str) -> dict[str, Any]:
    return {
        "$let": {
            "vars": {
                "values": {
                    "$map": {
                        "input": {"$cond": [{"$isArray": value}, value, []]},
                        "as": "item",
                        "in": _mstr(f"$$item.{field}"),
                    }
                }
            },
            "in": {
                "$ifNull": [
                    {
                        "$arrayElemAt": [
                            {
                                "$filter": {
                                    "input": "$$values",
                                    "as": "value",
                                    "cond": {"$ne": [{"$trim": {"input": "$$value"}}, ""]},
                                }
                            },
                            0,
                        ]
                    },
                    "",
                ]
            },
        }
    }


def _mongo_cve_affected(configurations: Any) -> dict[str, Any]:
    matches = {
        "$reduce": {
            "input": {"$cond": [{"$isArray": configurations}, configurations, []]},
            "initialValue": [],
            "in": {
                "$concatArrays": [
                    "$$value",
                    {
                        "$reduce": {
                            "input": {"$ifNull": ["$$this.nodes", []]},
                            "initialValue": [],
                            "in": {"$concatArrays": ["$$value", {"$ifNull": ["$$this.cpeMatch", []]}]},
                        }
                    },
                ]
            },
        }
    }
    return _mjoin_mapped(
        {
            "$filter": {
                "input": matches,
                "as": "match",
                "cond": {"$ne": ["$$match.vulnerable", False]},
            }
        },
        _mconcat_parts(
            [
                "$$item.criteria",
                _mbound("$$item.versionStartIncluding", ">="),
                _mbound("$$item.versionStartExcluding", ">"),
                _mbound("$$item.versionEndIncluding", "<="),
                _mbound("$$item.versionEndExcluding", "<"),
            ]
        ),
    )


def _mbound(value: Any, operator: str) -> dict[str, Any]:
    text = _mstr(value)
    return {"$cond": [{"$eq": [text, ""]}, "", {"$concat": [operator, text]}]}
