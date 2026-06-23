from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .mongo import redact_mongo_uri

SORT_SPEC: tuple[tuple[str, int], ...] = (
    ("updated_time", -1),
    ("disclosure_date", -1),
    ("type", 1),
    ("code", -1),
)

CATEGORICAL_BASE_FIELDS: tuple[str, ...] = (
    "type",
    "status",
    "severity",
    "vuln_type",
    "disclosure_date",
    "published_time",
    "updated_time",
)

TEXT_FIELDS: tuple[str, ...] = (
    "type",
    "code",
    "cve_code",
    "title",
)

DYNAMIC_ATTACK_METRICS_PATH: str | None = None

FILTER_FIELDS: dict[str, tuple[tuple[str, ...], tuple[str, ...], str | None]] = {
    "avd": (("type", "status", "severity", "vuln_type", "disclosure_date", "details.avd.danger_level", "details.avd.exploitability", "details.avd.patch_status", "details.avd.cwe.id", "details.avd.cwe.name", "details.avd.affected_software.vendor", "details.avd.affected_software.product", "details.avd.affected_software.version", "details.avd.affected_software.impact"), ("type", "code", "cve_code", "title", "details.avd.description", "details.avd.solution", "details.avd.impact_range", "details.avd.security_versions", "details.avd.reference_links"), "details.avd.attack_metrics"),
    "cisco": (("type", "status", "severity", "vuln_type", "disclosure_date", "details.cisco.sir", "details.cisco.status", "details.cisco.first_published", "details.cisco.cve_ids", "details.cisco.cwe", "details.cisco.product_names"), ("type", "code", "cve_code", "title", "details.cisco.advisory_id", "details.cisco.advisory_title", "details.cisco.summary", "details.cisco.cve_ids", "details.cisco.bug_ids", "details.cisco.cwe", "details.cisco.product_names", "details.cisco.publication_url"), None),
    "cnnvd": (("type", "status", "severity", "vuln_type", "disclosure_date", "details.cnnvd.publishTime", "details.cnnvd.updateTime", "details.cnnvd.hazardLevel", "details.cnnvd.vulType", "details.cnnvd.vulTypeName", "details.cnnvd.vendor", "details.cnnvd.affectedVendor", "details.cnnvd.cveCode"), ("code", "cve_code", "title", "details.cnnvd.id", "details.cnnvd.cnnvdCode", "details.cnnvd.vulName", "details.cnnvd.vulDesc", "details.cnnvd.affectedProduct", "details.cnnvd.affectedSystem", "details.cnnvd.productDesc", "details.cnnvd.patch", "details.cnnvd.referUrl"), None),
    "cnvd": (("type", "status", "severity", "vuln_type", "disclosure_date", "details.cnvd.severity", "details.cnvd.published_date", "details.cnvd.updated_date", "details.cnvd.affected_products", "details.cnvd.cve_ids"), ("code", "cve_code", "title", "details.cnvd.cnvd_id", "details.cnvd.description", "details.cnvd.solution", "details.cnvd.reference_links", "details.cnvd.raw_fields"), None),
    "cve": (("type", "severity", "disclosure_date", "details.cve.vuln_status", "details.cve.metrics.cvss_v40.cvssData.baseSeverity", "details.cve.metrics.cvss_v31.cvssData.baseSeverity", "details.cve.metrics.cvss_v30.cvssData.baseSeverity", "details.cve.metrics.cvss_v2.baseSeverity", "details.cve.weaknesses.descriptions.cweId", "details.cve.weaknesses.descriptions.description", "details.cve.references.tags"), ("type", "code", "title", "details.cve.cve_id", "details.cve.source_identifier", "details.cve.published", "details.cve.last_modified", "details.cve.descriptions.value", "details.cve.affected_products", "details.cve.references.url", "details.cve.configurations"), None),
    "github_advisory": (("type", "status", "severity", "cve_code", "details.github_advisory.advisory_type", "details.github_advisory.severity", "details.github_advisory.cve_ids", "details.github_advisory.vulnerabilities.package.ecosystem", "details.github_advisory.vulnerabilities.package.name", "details.github_advisory.cwes.cwe_id", "details.github_advisory.withdrawn_at"), ("title", "vuln_type", "details.github_advisory.ghsa_id", "details.github_advisory.cve_id", "details.github_advisory.cve_ids", "details.github_advisory.summary", "details.github_advisory.description", "details.github_advisory.html_url", "details.github_advisory.source_code_location", "details.github_advisory.references", "details.github_advisory.vulnerabilities.package.name"), None),
    "govcert": (("type", "status", "severity", "vuln_type", "disclosure_date", "details.govcert.alert_code", "details.govcert.alert_type", "details.govcert.published_date", "details.govcert.tags"), ("type", "code", "cve_code", "title", "details.govcert.description", "details.govcert.affected_systems", "details.govcert.impact", "details.govcert.recommendation", "details.govcert.more_information_links", "details.govcert.cve_ids", "details.govcert.raw_sections"), None),
    "hikvision": (("type", "status", "severity", "vuln_type", "disclosure_date", "details.hikvision.severity", "details.hikvision.published_date", "details.hikvision.updated_date", "details.hikvision.cve_ids", "details.hikvision.affected_products"), ("code", "cve_code", "title", "details.hikvision.advisory_id", "details.hikvision.summary", "details.hikvision.description", "details.hikvision.solution", "details.hikvision.reference_links"), None),
    "hkcert": (("type", "status", "severity", "disclosure_date", "details.hkcert.risk_level", "details.hkcert.bulletin_source", "details.hkcert.release_date", "details.hkcert.last_update_date"), ("type", "code", "cve_code", "title", "details.hkcert.intro", "details.hkcert.summary", "details.hkcert.note", "details.hkcert.impact", "details.hkcert.systems_affected", "details.hkcert.solutions", "details.hkcert.solution_links", "details.hkcert.related_links", "details.hkcert.table.name", "details.hkcert.table.impacts", "details.hkcert.table.details"), None),
    "huawei_sa": (("type", "status", "severity", "vuln_type", "disclosure_date", "details.huawei_sa.severity", "details.huawei_sa.lang", "details.huawei_sa.permission", "details.huawei_sa.sasnVersion"), ("type", "code", "cve_code", "title", "details.huawei_sa.summary", "details.huawei_sa.sasnNo", "details.huawei_sa.vul.hwPsirtId", "details.huawei_sa.vul.cveId", "details.huawei_sa.cve_ids"), None),
    "infosec": (("type", "status", "severity", "vuln_type", "details.infosec.alert_type", "details.infosec.alert_code", "details.infosec.tags", "details.infosec.affected_systems", "details.infosec.cve_ids"), ("code", "cve_code", "title", "details.infosec.summary", "details.infosec.description", "details.infosec.impact", "details.infosec.recommendation", "details.infosec.more_information_links", "details.infosec.govcert_detail_url"), None),
    "juniper": (("type", "status", "severity", "vuln_type", "disclosure_date", "details.juniper.article_type", "details.juniper.source_name", "details.juniper.published_date", "details.juniper.updated_date", "details.juniper.cve_ids", "details.juniper.products"), ("code", "cve_code", "title", "details.juniper.article_id", "details.juniper.summary", "details.juniper.description", "details.juniper.solution", "details.juniper.workaround", "details.juniper.reference_links"), None),
    "msrc": (("type", "status", "severity", "vuln_type", "disclosure_date", "cve_code", "details.msrc.document_id", "details.msrc.current_release_date", "details.msrc.cwe.id", "details.msrc.product_statuses.type", "details.msrc.product_statuses.product_names", "details.msrc.threats.type", "details.msrc.threats.description", "details.msrc.threats.product_names"), ("type", "code", "cve_code", "title", "vuln_type", "details.msrc.cve_id", "details.msrc.title", "details.msrc.description", "details.msrc.document_title", "details.msrc.notes.value", "details.msrc.cwe.value", "details.msrc.product_statuses.product_names", "details.msrc.threats.description", "details.msrc.remediations.description", "details.msrc.acknowledgments.names", "details.msrc.cvrf_url"), None),
    "paloalto": (("type", "status", "severity", "vuln_type", "details.paloalto.severity", "details.paloalto.urgency", "details.paloalto.products", "details.paloalto.cve_ids", "details.paloalto.weakness.cwe_id"), ("code", "cve_code", "title", "details.paloalto.advisory_id", "details.paloalto.description", "details.paloalto.solution", "details.paloalto.workarounds", "details.paloalto.exploitation_status", "details.paloalto.reference_links"), None),
    "qianxin": (("type", "status", "severity", "cve_code", "details.qianxin.category", "details.qianxin.level", "details.qianxin.threat_status", "details.qianxin.published_date", "details.qianxin.updated_date", "details.qianxin.vuln_ids", "details.qianxin.cve_ids", "details.qianxin.description.vulnerability_information.vendor", "details.qianxin.description.vulnerability_information.product", "details.qianxin.description.vulnerability_information.risk.qianxin_cert_rating", "details.qianxin.description.vulnerability_information.risk.risk_level", "details.qianxin.description.threat_assessment.cvss_3_1_rating"), ("title", "vuln_type", "details.qianxin.article_id", "details.qianxin.title", "details.qianxin.author", "details.qianxin.digest", "details.qianxin.description.security_advisory", "details.qianxin.description.vulnerability_information.summary", "details.qianxin.description.vulnerability_information.vulnerability_name", "details.qianxin.description.vulnerability_information.vulnerability_description", "details.qianxin.description.vulnerability_information.affected_versions", "details.qianxin.description.threat_assessment.impact_description", "details.qianxin.description.affected_assets", "details.qianxin.description.recommendations", "details.qianxin.description.references", "details.qianxin.reference_links"), None),
    "ransomwarelive": (("type", "status", "severity", "vuln_type", "disclosure_date", "details.ransomwarelive.group", "details.ransomwarelive.country", "details.ransomwarelive.activity", "details.ransomwarelive.attackdate", "details.ransomwarelive.discovered"), ("type", "code", "title", "details.ransomwarelive.victim", "details.ransomwarelive.group", "details.ransomwarelive.country", "details.ransomwarelive.activity", "details.ransomwarelive.website", "details.ransomwarelive.infostealer", "details.ransomwarelive.press", "details.ransomwarelive.permalink"), None),
    "splunk": (("type", "status", "severity", "disclosure_date", "cve_code", "details.splunk.severity", "details.splunk.published_date", "details.splunk.last_modified", "details.splunk.cwe", "details.splunk.affected_products", "details.splunk.fixed_versions", "details.splunk.cve_ids"), ("type", "code", "cve_code", "title", "vuln_type", "details.splunk.advisory_id", "details.splunk.description", "details.splunk.solution", "details.splunk.mitigations", "details.splunk.severity_summary", "details.splunk.severity_detail", "details.splunk.affected_versions", "details.splunk.all_affected_versions", "details.splunk.affected_components", "details.splunk.bug_ids", "details.splunk.oss", "details.splunk.credit", "details.splunk.packages", "details.splunk.product_status", "details.splunk.reference_links"), None),
    "zeroday": (("type", "status", "severity", "vuln_type", "disclosure_date", "details.zeroday.vulnerable_component", "details.zeroday.patch_status", "details.zeroday.disclosed_date", "details.zeroday.patched_date", "details.zeroday.cwe.id", "details.zeroday.cwe.name"), ("type", "code", "cve_code", "title", "details.zeroday.cve_id", "details.zeroday.advisory.title", "details.zeroday.advisory.url", "details.zeroday.cvss_v3_vector", "details.zeroday.description", "details.zeroday.reference_links"), None),
}


@dataclass
class MongoFilterState:
    selected_values: dict[str, set[str]] = field(default_factory=dict)
    text_filters: dict[str, str] = field(default_factory=dict)
    page: int = 0
    page_size: int = 10

    def toggle_value(self, field_name: str, value: str) -> None:
        values = self.selected_values.setdefault(field_name, set())
        if value in values:
            values.remove(value)
            if not values:
                self.selected_values.pop(field_name, None)
        else:
            values.add(value)
        self.page = 0

    def set_text_filter(self, field_name: str, value: str) -> None:
        value = value.strip()
        if value:
            self.text_filters[field_name] = value
        else:
            self.text_filters.pop(field_name, None)
        self.page = 0

    def clear_field(self, field_name: str) -> None:
        self.selected_values.pop(field_name, None)
        self.text_filters.pop(field_name, None)
        self.page = 0

    def build_query(self) -> dict[str, Any]:
        return build_mongo_query(self.selected_values, self.text_filters)

    def filters_payload(self) -> dict[str, Any]:
        return {
            "checkboxes": {
                field_name: sorted(values)
                for field_name, values in sorted(self.selected_values.items())
                if values
            },
            "text": {
                field_name: value
                for field_name, value in sorted(self.text_filters.items())
                if value
            },
        }


def build_mongo_query(
    selected_values: dict[str, set[str]],
    text_filters: dict[str, str],
) -> dict[str, Any]:
    clauses: list[dict[str, Any]] = []

    for field_name, values in sorted(selected_values.items()):
        cleaned = sorted(str(value) for value in values if str(value))
        if not cleaned:
            continue
        if len(cleaned) == 1:
            clauses.append({field_name: cleaned[0]})
        else:
            clauses.append({field_name: {"$in": cleaned}})

    for field_name, value in sorted(text_filters.items()):
        value = value.strip()
        if value:
            clauses.append({field_name: {"$regex": re.escape(value), "$options": "i"}})

    if not clauses:
        return {}
    if len(clauses) == 1:
        return clauses[0]
    return {"$and": clauses}


def filter_fields_for_provider(provider_key: str) -> tuple[tuple[str, ...], tuple[str, ...], str | None]:
    fields = FILTER_FIELDS.get(provider_key)
    if fields is None:
        return CATEGORICAL_BASE_FIELDS, TEXT_FIELDS, DYNAMIC_ATTACK_METRICS_PATH

    categorical_fields = _dedupe_fields((*CATEGORICAL_BASE_FIELDS, *fields[0]))
    text_fields = fields[1]
    dynamic_path = fields[2]
    return categorical_fields, text_fields, dynamic_path


def _dedupe_fields(fields: tuple[str, ...]) -> tuple[str, ...]:
    result: list[str] = []
    seen: set[str] = set()
    for field in fields:
        if field in seen:
            continue
        result.append(field)
        seen.add(field)
    return tuple(result)


def available_categorical_fields(
    collection: Any,
    *,
    base_fields: tuple[str, ...] = CATEGORICAL_BASE_FIELDS,
    dynamic_object_path: str | None = DYNAMIC_ATTACK_METRICS_PATH,
    sample_size: int = 500,
) -> tuple[str, ...]:
    dynamic_fields = set()
    if dynamic_object_path:
        dynamic_fields = {
            f"{dynamic_object_path}.{key}"
            for key in _discover_object_keys(collection, dynamic_object_path, sample_size=sample_size)
        }
    return tuple(sorted((*base_fields, *dynamic_fields)))


def distinct_values(collection: Any, field_name: str, *, limit: int = 200) -> list[str]:
    values = collection.distinct(field_name)
    unique = {
        str(value)
        for value in _flatten(values)
        if value is not None and str(value).strip()
    }
    return sorted(unique, key=lambda value: value.casefold())[:limit]


def fetch_filtered_records(
    collection: Any,
    state: MongoFilterState,
    *,
    limit: int | None = None,
) -> list[dict[str, Any]]:
    query = state.build_query()
    cursor = collection.find(query).sort(list(SORT_SPEC))
    if limit is not None:
        cursor = cursor.limit(limit)
    return [strip_mongo_id(item) for item in cursor]


def fetch_filtered_page(
    collection: Any,
    state: MongoFilterState,
) -> tuple[int, list[dict[str, Any]]]:
    query = state.build_query()
    total = collection.count_documents(query)
    cursor = (
        collection.find(query)
        .sort(list(SORT_SPEC))
        .skip(state.page * state.page_size)
        .limit(state.page_size)
    )
    return total, [strip_mongo_id(item) for item in cursor]


def export_filtered_results(
    collection: Any,
    state: MongoFilterState,
    *,
    output_path: Path,
    mongo_uri: str,
    mongo_database: str,
    mongo_collection: str,
    limit: int | None = None,
) -> dict[str, Any]:
    vulnerabilities = fetch_filtered_records(collection, state, limit=limit)
    payload = {
        "filtered_at": datetime.now(UTC).isoformat(),
        "mongo": {
            "uri": redact_mongo_uri(mongo_uri) or mongo_uri,
            "database": mongo_database,
            "collection": mongo_collection,
        },
        "filters": state.filters_payload(),
        "result_count": len(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return payload


def strip_mongo_id(document: dict[str, Any]) -> dict[str, Any]:
    result = dict(document)
    result.pop("_id", None)
    return result


def _discover_object_keys(collection: Any, field_path: str, *, sample_size: int) -> set[str]:
    keys: set[str] = set()
    try:
        cursor = collection.find(
            {field_path: {"$type": "object"}},
            {field_path: 1},
        ).limit(sample_size)
    except Exception:
        return keys

    for document in cursor:
        metrics = _value_at_path(document, field_path)
        if isinstance(metrics, dict):
            keys.update(str(key) for key in metrics if key)
    return keys


def _value_at_path(document: dict[str, Any], field_name: str) -> Any:
    value: Any = document
    for part in field_name.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _flatten(values: Any) -> list[Any]:
    if isinstance(values, list):
        result: list[Any] = []
        for value in values:
            result.extend(_flatten(value))
        return result
    return [values]
