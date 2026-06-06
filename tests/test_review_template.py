import json

import pytest

from vuln_scraper.review_template import (
    REVIEW_TEMPLATE_FIELDS,
    ReviewViewError,
    ensure_review_view,
    review_template_from_document,
    review_view_name,
    review_view_pipeline,
)


def document(provider: str, detail: dict, *, cve_code: str | None = None) -> dict:
    return {
        "_id": f"{provider}:code",
        "type": provider,
        "code": "code",
        "title": f"{provider} title",
        "cve_code": cve_code,
        "details": {provider: detail},
    }


def test_review_template_uses_exact_seven_field_schema() -> None:
    template = review_template_from_document(document("avd", {}))

    assert tuple(template) == REVIEW_TEMPLATE_FIELDS == (
        "title",
        "description",
        "impacts",
        "affected",
        "cve",
        "recommendation",
        "related_link",
    )
    assert "external" not in template
    assert "filename" not in template
    assert isinstance(template["affected"], list)
    assert isinstance(template["related_link"], list)
    assert all(
        isinstance(template[field], str)
        for field in REVIEW_TEMPLATE_FIELDS
        if field not in {"affected", "related_link"}
    )


def test_avd_uses_danger_level_and_software_without_impact_text() -> None:
    template = review_template_from_document(
        document(
            "avd",
            {
                "danger_level": "高危",
                "description": "Description",
                "impact_range": ["Must not appear"],
                "affected_software": [
                    {"vendor": "Acme", "product": "Widget", "version": "1.0", "impact": "RCE"}
                ],
                "cve_id": "CVE-2026-1000",
                "solution": "Upgrade",
                "reference_links": ["https://one"],
            },
        )
    )

    assert template["impacts"] == "高危"
    assert template["affected"] == ["Acme Widget 1.0"]
    assert template["related_link"] == ["https://one"]


def test_hkcert_uses_risk_level_and_product_table_then_system_fallback() -> None:
    table_template = review_template_from_document(
        document(
            "hkcert",
            {
                "risk_level": "High Risk",
                "table": [{"name": "Product", "risk_level": "Medium", "details": "< 2.0"}],
                "systems_affected": ["Fallback system"],
            },
        )
    )
    fallback_template = review_template_from_document(
        document("hkcert", {"table": [], "systems_affected": ["Windows Server"]})
    )

    assert table_template["impacts"] == "High Risk"
    assert table_template["affected"] == ["Product < 2.0"]
    assert fallback_template["affected"] == ["Windows Server"]


def test_cve_uses_cvss_severity_and_vulnerable_cpe_version_bounds() -> None:
    template = review_template_from_document(
        document(
            "cve",
            {
                "cve_id": "CVE-2026-3000",
                "metrics": {"cvss_v31": [{"cvssData": {"baseSeverity": "HIGH"}}]},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:*",
                                        "versionStartIncluding": "1.0",
                                        "versionEndExcluding": "2.0",
                                    },
                                    {"vulnerable": False, "criteria": "ignored"},
                                ]
                            }
                        ]
                    }
                ],
            },
        )
    )

    assert template["impacts"] == "HIGH"
    assert template["affected"] == ["cpe:2.3:a:acme:widget:*:*:*:*:*:*:*:* >=1.0 <2.0"]


def test_cve_v5_uses_normalized_affected_product_versions() -> None:
    template = review_template_from_document(
        document(
            "cve",
            {
                "cve_id": "CVE-2026-3000",
                "descriptions": [{"lang": "en", "value": "Description"}],
                "metrics": {"cvss_v40": [{"cvssData": {"baseSeverity": "CRITICAL"}}]},
                "affected_products": ["Acme Widget 1.0 <2.0 (semver)"],
                "references": [{"url": "https://example.test/advisory"}],
            },
        )
    )

    assert template["impacts"] == "CRITICAL"
    assert template["affected"] == ["Acme Widget 1.0 <2.0 (semver)"]
    assert template["related_link"] == ["https://example.test/advisory"]
    assert "affected_products" in json.dumps(review_view_pipeline("cve"))


def test_github_advisory_maps_severity_packages_and_patch_versions() -> None:
    template = review_template_from_document(
        document(
            "github_advisory",
            {
                "severity": "high",
                "vulnerabilities": [
                    {
                        "package": {"ecosystem": "npm", "name": "example"},
                        "vulnerable_version_range": "< 2.0",
                        "first_patched_version": "2.0",
                    }
                ],
            },
        )
    )

    assert template["impacts"] == "high"
    assert template["affected"] == ["npm:example < 2.0"]
    assert template["recommendation"] == "2.0"


def test_cisco_description_strips_paragraph_html_tags() -> None:
    template = review_template_from_document(
        document(
            "cisco",
            {"summary": '<p>First paragraph.</p><P class="notice">Second paragraph.</P>'},
        )
    )

    assert template["description"] == "First paragraph.Second paragraph."


def test_related_link_is_an_array_of_non_empty_links() -> None:
    template = review_template_from_document(
        document(
            "cisco",
            {
                "publication_url": "https://publication",
                "cvrf_url": "",
                "csaf_url": "https://csaf",
            },
        )
    )

    assert template["related_link"] == ["https://publication", "https://csaf"]


def test_qianxin_maps_structured_chapters_into_the_seven_review_fields() -> None:
    template = review_template_from_document(
        document(
            "qianxin",
            {
                "description": {
                    "security_advisory": "Security advisory",
                    "vulnerability_information": {
                        "summary": "Summary",
                        "vulnerability_description": "Vulnerability description",
                        "vendor": "Acme",
                        "product": "Widget",
                        "affected_versions": ["Widget < 2.0", "Widget 3.0"],
                        "other_affected_components": "无",
                        "cve_id": "CVE-2026-12345",
                        "risk": {"qianxin_cert_rating": "高危"},
                    },
                    "threat_assessment": {"impact_description": "Impact description"},
                    "affected_assets": "Affected asset summary",
                    "recommendations": ["Upgrade", "Restrict access"],
                    "references": ["Reference"],
                },
                "reference_links": ["https://example.test/advisory"],
            },
        )
    )

    assert tuple(template) == REVIEW_TEMPLATE_FIELDS
    assert template["description"] == (
        "Security advisory\nSummary\nVulnerability description\nImpact description\nAffected asset summary"
    )
    assert template["impacts"] == "高危"
    assert template["affected"] == ["Acme Widget", "Widget < 2.0", "Widget 3.0"]
    assert template["cve"] == "CVE-2026-12345"
    assert template["recommendation"] == "Upgrade\nRestrict access"
    assert template["related_link"] == ["https://example.test/advisory"]

    pipeline = json.dumps(review_view_pipeline("qianxin"))
    assert "description.vulnerability_information.affected_versions" in pipeline
    assert "description.recommendations" in pipeline


def test_cisco_review_view_strips_paragraph_html_tags_with_supported_operators() -> None:
    description = review_view_pipeline("cisco")[0]["$project"]["description"]

    assert "$regexReplace" not in json.dumps(description)
    assert json.dumps(description).count("$replaceAll") == 4


@pytest.mark.parametrize("provider", ["zeroday", "govcert", "infosec", "ransomwarelive", "cnnvd"])
def test_providers_without_reliable_severity_have_blank_impacts(provider: str) -> None:
    template = review_template_from_document(
        document(provider, {"impact": "Impact prose", "activity": "Healthcare", "severity_counts": {"High": 2}})
    )

    assert template["impacts"] == ""


@pytest.mark.parametrize("provider", ["huawei_sa", "ransomwarelive", "cnnvd"])
def test_providers_without_normalized_products_have_blank_affected(provider: str) -> None:
    template = review_template_from_document(
        document(provider, {"raw_sections": {"affected": "raw"}, "victim": "Company", "vul": [{"cveId": "x"}]})
    )

    assert template["affected"] == []


@pytest.mark.parametrize(
    ("provider", "detail", "severity", "affected"),
    [
        ("cisco", {"sir": "Critical", "product_names": ["IOS XE"]}, "Critical", "IOS XE"),
        ("huawei_sa", {"severity": "High", "vul": [{"cveId": "CVE-1"}]}, "High", ""),
        ("paloalto", {"severity": "HIGH", "products": ["PAN-OS"]}, "HIGH", "PAN-OS"),
        ("qianxin", {"level": "Critical", "description": {}}, "Critical", ""),
        (
            "splunk",
            {
                "severity": "Medium",
                "affected_products": "Splunk Enterprise",
                "affected_versions": "< 9.0",
                "product_status": [{"product": "Splunk", "base_version": "9", "affected_version": "9.0.0"}],
            },
            "Medium",
            "Splunk Enterprise\n< 9.0\nSplunk 9 9.0.0",
        ),
        ("hikvision", {"severity": "High", "affected_products": ["Camera A"]}, "High", "Camera A"),
        ("cnvd", {"severity": "中", "affected_products": ["Product A"]}, "中", "Product A"),
        (
            "juniper",
            {"raw_fields": {"severity": "Critical"}, "products": ["Junos OS"]},
            "Critical",
            "Junos OS",
        ),
    ],
)
def test_provider_severity_and_affected_sources(
    provider: str,
    detail: dict,
    severity: str,
    affected: str,
) -> None:
    template = review_template_from_document(document(provider, detail))

    assert template["impacts"] == severity
    assert template["affected"] == ([line for line in affected.split("\n") if line] if affected else [])


@pytest.mark.parametrize(
    "provider",
    [
        "avd",
        "hkcert",
        "cve",
        "cisco",
        "github_advisory",
        "zeroday",
        "govcert",
        "infosec",
        "huawei_sa",
        "paloalto",
        "qianxin",
        "ransomwarelive",
        "splunk",
        "hikvision",
        "cnnvd",
        "cnvd",
        "juniper",
    ],
)
def test_every_provider_returns_exact_string_schema(provider: str) -> None:
    template = review_template_from_document(document(provider, {}))

    assert tuple(template) == REVIEW_TEMPLATE_FIELDS
    assert isinstance(template["affected"], list)
    assert isinstance(template["related_link"], list)
    assert all(
        isinstance(template[field], str)
        for field in REVIEW_TEMPLATE_FIELDS
        if field not in {"affected", "related_link"}
    )


def test_review_view_pipeline_projects_exact_schema() -> None:
    project = review_view_pipeline("avd")[0]["$project"]

    assert project["_id"] == 0
    assert tuple(key for key in project if key != "_id") == REVIEW_TEMPLATE_FIELDS
    assert "external" not in project
    assert "filename" not in project


def test_ensure_review_view_creates_view_for_existing_collection() -> None:
    database = FakeDatabase({"avd": []}, types={"avd": "collection"})

    created = ensure_review_view(database, provider="avd", collection_name="avd")

    assert created
    assert database.commands[0]["create"] == "avd_review"
    assert database.commands[0]["viewOn"] == "avd"
    assert database.types["avd_review"] == "view"


def test_ensure_review_view_replaces_existing_view() -> None:
    database = FakeDatabase(
        {"avd": [], "avd_review": []},
        types={"avd": "collection", "avd_review": "view"},
    )

    assert ensure_review_view(database, provider="avd", collection_name="avd")
    assert database.dropped == ["avd_review"]
    assert database.types["avd_review"] == "view"


def test_ensure_review_view_skips_missing_source_and_protects_collection_collision() -> None:
    missing = FakeDatabase({}, types={})
    collision = FakeDatabase(
        {"avd": [], "avd_review": []},
        types={"avd": "collection", "avd_review": "collection"},
    )

    assert not ensure_review_view(missing, provider="avd", collection_name="avd")
    with pytest.raises(ReviewViewError):
        ensure_review_view(collision, provider="avd", collection_name="avd")


class FakeCursor:
    def __init__(self, documents: list[dict]) -> None:
        self.documents = documents

    def limit(self, limit: int) -> "FakeCursor":
        self.documents = self.documents[:limit]
        return self

    def __iter__(self):
        return iter(self.documents)


class FakeCollection:
    def __init__(self, database: "FakeDatabase", name: str) -> None:
        self.database = database
        self.name = name

    def find(self, query: dict) -> FakeCursor:
        return FakeCursor(list(self.database.collections.get(self.name, [])))

    def drop(self) -> None:
        self.database.dropped.append(self.name)
        self.database.collections.pop(self.name, None)
        self.database.types.pop(self.name, None)


class FakeDatabase:
    def __init__(
        self,
        collections: dict[str, list[dict]],
        *,
        types: dict[str, str] | None = None,
    ) -> None:
        self.collections = collections
        self.types = types or {name: "collection" for name in collections}
        self.commands: list[dict] = []
        self.dropped: list[str] = []

    def __getitem__(self, name: str) -> FakeCollection:
        return FakeCollection(self, name)

    def list_collections(self, filter: dict):
        return [{"name": name, "type": collection_type} for name, collection_type in self.types.items()]

    def command(self, command: dict) -> None:
        self.commands.append(command)
        self.types[command["create"]] = "view"
        self.collections.setdefault(command["create"], [])
