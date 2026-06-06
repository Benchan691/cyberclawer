import copy
import json
import re

from vuln_scraper.mongo_filter import (
    MongoFilterState,
    available_categorical_fields,
    build_mongo_query,
    distinct_values,
    export_filtered_results,
    fetch_filtered_page,
    filter_fields_for_provider,
)
from vuln_scraper.tui import _dedupe_fields, _sanitize_curses_text


def test_build_mongo_query_combines_checkbox_or_and_text_contains() -> None:
    query = build_mongo_query(
        {
            "status": {"CVE PoC", "CVE EXP"},
            "details.avd.affected_software.product": {"nginx"},
        },
        {"title": "remote code"},
    )

    assert query == {
        "$and": [
            {"details.avd.affected_software.product": "nginx"},
            {"status": {"$in": ["CVE EXP", "CVE PoC"]}},
            {"title": {"$regex": "remote\\ code", "$options": "i"}},
        ]
    }


def test_filter_state_toggles_values_and_text() -> None:
    state = MongoFilterState(page=2)

    state.toggle_value("status", "CVE PoC")
    state.set_text_filter("title", "nginx")

    assert state.selected_values == {"status": {"CVE PoC"}}
    assert state.text_filters == {"title": "nginx"}
    assert state.page == 0

    state.clear_field("status")

    assert state.selected_values == {}


def test_fetch_filtered_page_is_array_aware_sorted_and_paginated() -> None:
    collection = FakeFilterCollection(
        [
            record("AVD-2026-10001", "2026-01-01", "CVE PoC", "nginx issue", product="nginx"),
            record("AVD-2026-10003", "2026-01-03", "CVE PoC", "nginx remote", product="nginx"),
            record("AVD-2026-10002", "2026-01-02", "CVE EXP", "openssl remote", product="openssl"),
        ]
    )
    state = MongoFilterState(
        selected_values={"details.avd.affected_software.product": {"nginx"}},
        text_filters={"title": "remote"},
        page_size=1,
    )

    total, first_page = fetch_filtered_page(collection, state)
    state.page = 1
    _, second_page = fetch_filtered_page(collection, state)

    assert total == 1
    assert [f"{item['type']}:{item['code']}" for item in first_page] == ["avd:2026-10003"]
    assert second_page == []


def test_distinct_values_and_dynamic_attack_metric_fields() -> None:
    collection = FakeFilterCollection(
        [
            record("AVD-2026-10001", "2026-01-01", "CVE PoC", "nginx", product="nginx"),
            record("AVD-2026-10002", "2026-01-02", "CVE EXP", "openssl", product="openssl"),
        ]
    )

    assert distinct_values(collection, "details.avd.affected_software.product") == ["nginx", "openssl"]
    assert "details.avd.attack_metrics.patch_status" in available_categorical_fields(
        collection,
        dynamic_object_path="details.avd.attack_metrics",
    )


def test_filter_fields_for_provider_uses_avd_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("avd")

    assert "details.avd.danger_level" in categorical_fields
    assert "details.avd.affected_software.product" in categorical_fields
    assert "details.avd.description" in text_fields
    assert "details.avd.reference_links" in text_fields
    assert dynamic_path == "details.avd.attack_metrics"


def test_filter_fields_for_provider_uses_hkcert_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("hkcert")

    assert "details.hkcert.risk_level" in categorical_fields
    assert "cve_code" not in categorical_fields
    assert "cve_code" in text_fields
    assert "details.hkcert.solutions" in text_fields
    assert "details.hkcert.summary" in text_fields
    assert "details.hkcert.table.name" in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_zeroday_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("zeroday")

    assert "details.zeroday.vulnerable_component" in categorical_fields
    assert "details.zeroday.cwe.id" in categorical_fields
    assert "details.zeroday.description" in text_fields
    assert "details.zeroday.reference_links" in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_govcert_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("govcert")

    assert "details.govcert.alert_type" in categorical_fields
    assert "details.govcert.tags" in categorical_fields
    assert "details.govcert.description" in text_fields
    assert "details.govcert.cve_ids" in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_github_advisory_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("github_advisory")

    assert "details.github_advisory.severity" in categorical_fields
    assert "details.github_advisory.vulnerabilities.package.ecosystem" in categorical_fields
    assert "details.github_advisory.description" in text_fields
    assert "details.github_advisory.references" in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_cisco_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("cisco")

    assert "details.cisco.sir" in categorical_fields
    assert "details.cisco.product_names" in categorical_fields
    assert "details.cisco.summary" in text_fields
    assert "details.cisco.publication_url" in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_paloalto_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("paloalto")

    assert "details.paloalto.severity" in categorical_fields
    assert "details.paloalto.products" in categorical_fields
    assert "details.paloalto.description" in text_fields
    assert "details.paloalto.reference_links" in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_ransomwarelive_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("ransomwarelive")

    assert "details.ransomwarelive.group" in categorical_fields
    assert "details.ransomwarelive.country" in categorical_fields
    assert "details.ransomwarelive.website" in text_fields
    assert "details.ransomwarelive.permalink" in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_infosec_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("infosec")

    assert "details.infosec.alert_type" in categorical_fields
    assert "details.infosec.tags" in categorical_fields
    assert "details.infosec.summary" in text_fields
    assert "details.infosec.govcert_detail_url" in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_splunk_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("splunk")

    assert "details.splunk.severity" in categorical_fields
    assert "details.splunk.cve_ids" in categorical_fields
    assert "details.splunk.description" in text_fields
    assert "details.splunk.product_status" in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_hikvision_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("hikvision")

    assert "details.hikvision.severity" in categorical_fields
    assert "details.hikvision.affected_products" in categorical_fields
    assert "details.hikvision.description" in text_fields
    assert "details.hikvision.reference_links" in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_cnnvd_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("cnnvd")

    assert "details.cnnvd.created_by" in categorical_fields
    assert "details.cnnvd.cve_ids" in categorical_fields
    assert "details.cnnvd.description" in text_fields
    assert "details.cnnvd.reference_links" in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_qianxin_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("qianxin")

    assert "details.qianxin.level" in categorical_fields
    assert "details.qianxin.threat_status" in categorical_fields
    assert "details.qianxin.description.security_advisory" in text_fields
    assert "details.qianxin.description.vulnerability_information.affected_versions" in text_fields
    assert "details.qianxin.description.recommendations" in text_fields
    assert "details.qianxin.reference_links" in text_fields
    assert "details.qianxin.raw_sections" not in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_cnvd_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("cnvd")

    assert "details.cnvd.severity" in categorical_fields
    assert "details.cnvd.affected_products" in categorical_fields
    assert "details.cnvd.description" in text_fields
    assert "details.cnvd.reference_links" in text_fields
    assert dynamic_path is None


def test_filter_fields_for_provider_uses_juniper_fields() -> None:
    categorical_fields, text_fields, dynamic_path = filter_fields_for_provider("juniper")

    assert "details.juniper.article_type" in categorical_fields
    assert "details.juniper.products" in categorical_fields
    assert "details.juniper.description" in text_fields
    assert "details.juniper.reference_links" in text_fields
    assert dynamic_path is None


def test_sanitize_curses_text_strips_control_characters() -> None:
    assert _sanitize_curses_text("line\x00with\x07controls") == "line with controls"
    assert _sanitize_curses_text("【漏洞通报】CNNVD") == "【漏洞通报】CNNVD"


def test_tui_field_list_deduplicates_overlapping_fields() -> None:
    assert _dedupe_fields(("type", "status", "type", "cve_code", "cve_code")) == (
        "type",
        "status",
        "cve_code",
    )


def test_export_filtered_results_writes_expected_payload(tmp_path) -> None:
    collection = FakeFilterCollection(
        [
            record("AVD-2026-10001", "2026-01-01", "CVE PoC", "nginx remote", product="nginx"),
            record("AVD-2026-10002", "2026-01-02", "CVE EXP", "openssl remote", product="openssl"),
        ]
    )
    state = MongoFilterState(
        selected_values={"details.avd.affected_software.product": {"nginx"}},
        text_filters={"title": "remote"},
    )
    output_path = tmp_path / "filtered.json"

    payload = export_filtered_results(
        collection,
        state,
        output_path=output_path,
        mongo_uri="mongodb://localhost:27017",
        mongo_database="avd",
        mongo_collection="vulnerabilities",
    )

    assert payload["result_count"] == 1
    assert payload["mongo"] == {
        "uri": "mongodb://localhost:27017",
        "database": "avd",
        "collection": "vulnerabilities",
    }
    assert payload["filters"] == {
        "checkboxes": {"details.avd.affected_software.product": ["nginx"]},
        "text": {"title": "remote"},
    }
    assert [item["code"] for item in payload["vulnerabilities"]] == ["2026-10001"]

    written = json.loads(output_path.read_text(encoding="utf-8"))
    assert written["result_count"] == 1
    assert written["vulnerabilities"][0]["type"] == "avd"


def record(avd_id: str, disclosure_date: str, status: str, title: str, *, product: str) -> dict:
    code = avd_id.removeprefix("AVD-")
    return {
        "_id": f"avd:{code}",
        "type": "avd",
        "code": code,
        "cve_code": code,
        "title": title,
        "vuln_type": "CWE-78",
        "disclosure_date": disclosure_date,
        "status": status,
        "details": {
            "avd": {
                "attack_metrics": {"patch_status": "official"},
                "affected_software": [{"product": product, "vendor": "vendor"}],
            }
        },
    }


class FakeFilterCollection:
    def __init__(self, documents: list[dict]) -> None:
        self.documents = [copy.deepcopy(document) for document in documents]

    def count_documents(self, query: dict) -> int:
        return len([document for document in self.documents if matches(document, query)])

    def find(self, query: dict | None = None, projection: dict | None = None) -> "FakeCursor":
        query = query or {}
        documents = [copy.deepcopy(document) for document in self.documents if matches(document, query)]
        return FakeCursor(documents)

    def distinct(self, field_name: str) -> list:
        values = []
        for document in self.documents:
            values.extend(values_at_path(document, field_name))
        return values


class FakeCursor:
    def __init__(self, documents: list[dict]) -> None:
        self.documents = documents

    def sort(self, sort_spec: list[tuple[str, int]]) -> "FakeCursor":
        for field_name, direction in reversed(sort_spec):
            self.documents.sort(
                key=lambda document: str(first_value(document, field_name) or ""),
                reverse=direction < 0,
            )
        return self

    def skip(self, count: int) -> "FakeCursor":
        self.documents = self.documents[count:]
        return self

    def limit(self, count: int) -> "FakeCursor":
        self.documents = self.documents[:count]
        return self

    def __iter__(self):
        return iter(self.documents)


def matches(document: dict, query: dict) -> bool:
    if not query:
        return True
    if "$and" in query:
        return all(matches(document, clause) for clause in query["$and"])
    for field_name, expected in query.items():
        values = values_at_path(document, field_name)
        if isinstance(expected, dict) and "$in" in expected:
            if not any(value in expected["$in"] for value in values):
                return False
        elif isinstance(expected, dict) and "$regex" in expected:
            flags = re.IGNORECASE if "i" in expected.get("$options", "") else 0
            pattern = re.compile(expected["$regex"], flags)
            if not any(pattern.search(str(value)) for value in values):
                return False
        elif isinstance(expected, dict) and expected.get("$type") == "object":
            if not any(isinstance(value, dict) for value in values):
                return False
        elif not any(value == expected for value in values):
            return False
    return True


def values_at_path(document: dict, field_name: str) -> list:
    values = [document]
    for part in field_name.split("."):
        next_values = []
        for value in values:
            if isinstance(value, dict) and part in value:
                next_values.append(value[part])
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, dict) and part in item:
                        next_values.append(item[part])
        values = next_values
    return flatten(values)


def value_at_path(document: dict, field_name: str):
    values = values_at_path(document, field_name)
    return values[0] if values else None


def first_value(document: dict, field_name: str):
    return value_at_path(document, field_name)


def flatten(values: list) -> list:
    result = []
    for value in values:
        if isinstance(value, list):
            result.extend(flatten(value))
        else:
            result.append(value)
    return result
