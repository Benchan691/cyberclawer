import json

import pytest

from vuln_scraper.review_template import (
    REVIEW_TEMPLATE_FIELDS,
    _review_document_errors,
    review_template_from_document,
    review_view_pipeline,
)


def document(provider: str, detail: dict, *, cve_code: str | None = None) -> dict:
    code = (
        cve_code.removeprefix("CVE-")
        if provider == "cve" and cve_code
        else "code"
    )
    result = {
        "_id": f"{provider}:code",
        "schema_version": 2,
        "code": code,
        "title": f"{provider} title",
        "details": detail,
    }
    if provider != "cve" and cve_code:
        result["cve_ids"] = [cve_code]
    return result


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

    assert template["impacts"] == "High"
    assert template["affected"] == ["Acme Widget 1.0"]
    assert template["related_link"] == ["https://one"]


def test_hkcert_uses_risk_level_and_product_table_then_system_fallback() -> None:
    table_template = review_template_from_document(
        {
            **document(
                "hkcert",
                {
                    "risk_level": "High Risk",
                    "table": [{"name": "Product", "risk_level": "Medium", "details": "< 2.0"}],
                    "systems_affected": ["Fallback system"],
                    "vulnerability_identifiers": [
                        {"cve_id": "CVE-2026-1000"},
                        {"cve_id": "CVE-2026-2000"},
                    ],
                },
            ),
            "cve_ids": ["CVE-2026-1000", "CVE-2026-2000"],
        }
    )
    fallback_template = review_template_from_document(
        document("hkcert", {"table": [], "systems_affected": ["Windows Server"]})
    )

    assert table_template["impacts"] == "High"
    assert table_template["affected"] == ["Product < 2.0"]
    assert table_template["cve"] == "CVE-2026-1000\nCVE-2026-2000"
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

    assert template["impacts"] == "High"
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

    assert template["impacts"] == "Critical"
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

    assert template["impacts"] == "High"
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


def test_nvd_review_template_maps_description_metrics_and_links() -> None:
    template = review_template_from_document(
        document(
            "nvd",
            {
                "cve_id": "CVE-2026-1234",
                "title": "Outline OAuth logic error",
                "description": "A logic error in OAuthInterface allows account takeover.",
                "vuln_status": "Modified",
                "severity": "HIGH",
                "base_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "published_date": "2026-05-11",
                "last_modified": "2026-05-20",
                "cwe_ids": ["CWE-284"],
                "reference_links": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
                    "https://github.com/advisory",
                ],
                "affected_products": ["cpe:2.3:a:outline:outline:1.6.1:*:*:*:*:*:*:*:*"],
                "detail_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
            },
            cve_code="CVE-2026-1234",
        )
    )

    assert template["description"] == "A logic error in OAuthInterface allows account takeover."
    assert template["impacts"] == "High"
    assert template["affected"] == ["cpe:2.3:a:outline:outline:1.6.1:*:*:*:*:*:*:*:*"]
    assert template["cve"] == "CVE-2026-1234"
    assert template["recommendation"] == ""
    assert template["related_link"] == [
        "https://nvd.nist.gov/vuln/detail/CVE-2026-1234",
        "https://github.com/advisory",
    ]

    pipeline = json.dumps(review_view_pipeline("nvd"))
    assert "$details.description" in pipeline
    assert "$details.affected_products" in pipeline
    assert "$details.reference_links" in pipeline


def test_hikvision_prefers_summary_for_review_description() -> None:
    template = review_template_from_document(
        document(
            "hikvision",
            {
                "summary": "AEM rte advisory body",
                "description": "Parsed Description section only",
                "severity": "High",
                "affected_products": ["Camera A"],
                "solution": "Upgrade firmware",
                "cve_ids": ["CVE-2026-1234"],
                "reference_links": ["https://www.hikvision.com/advisory"],
            },
            cve_code="CVE-2026-1234",
        )
    )

    assert template["description"] == "AEM rte advisory body"
    assert template["impacts"] == "High"
    assert template["affected"] == ["Camera A"]
    assert template["cve"] == "CVE-2026-1234"
    assert template["recommendation"] == "Upgrade firmware"
    assert template["related_link"] == ["https://www.hikvision.com/advisory"]

    pipeline = json.dumps(review_view_pipeline("hikvision"))
    assert "$details.summary" in pipeline
    assert pipeline.index("$details.summary") < pipeline.index(
        "$details.description"
    )


def test_cnvd_review_impacts_uses_envelope_severity() -> None:
    template = review_template_from_document(
        {
            **document("cnvd", {"severity": "低", "affected_products": ["Product A"]}),
            "severity": "Medium",
        }
    )

    assert template["impacts"] == "Medium"

    pipeline = json.dumps(review_view_pipeline("cnvd"))
    assert '"$severity"' in pipeline
    assert '"$status"' not in pipeline


def test_splunk_review_description_includes_description_tables() -> None:
    template = review_template_from_document(
        document(
            "splunk",
            {
                "description": "Several package updates address CVEs.",
                "description_tables": [
                    {
                        "headers": ["package", "remediation", "cve", "severity"],
                        "rows": [
                            {
                                "package": "commons-lang3",
                                "remediation": "Upgrade to 3.18.0",
                                "cve": "CVE-2025-48924",
                                "severity": "Medium",
                            }
                        ],
                    }
                ],
                "severity": "Medium",
            },
        )
    )

    assert template["description"].startswith("Several package updates address CVEs.")
    assert "package | remediation | cve | severity" in template["description"]
    assert "commons-lang3 | Upgrade to 3.18.0 | CVE-2025-48924 | Medium" in template["description"]

    pipeline = json.dumps(review_view_pipeline("splunk"))
    assert "description_tables" in pipeline
    assert "$getField" not in pipeline


def test_cnnvd_related_link_extracts_urls_from_refer_url() -> None:
    template = review_template_from_document(
        document(
            "cnnvd",
            {
                "referUrl": "来源: Google\r\n链接:https://example.test/advisory",
                "patch": "https://example.test/patch",
            },
        )
    )

    assert template["related_link"] == ["https://example.test/advisory"]
    assert "https://example.test/patch" not in template["related_link"]

    pipeline = json.dumps(review_view_pipeline("cnnvd"))
    assert "$details.referUrl" in pipeline
    assert "regexFindAll" in pipeline


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
    assert template["impacts"] == "High"
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


@pytest.mark.parametrize("provider", ["zeroday", "govcert", "infosec", "ransomwarelive"])
def test_providers_without_reliable_severity_have_blank_impacts(provider: str) -> None:
    template = review_template_from_document(
        document(provider, {"impact": "Impact prose", "activity": "Healthcare", "severity_counts": {"High": 2}})
    )

    assert template["impacts"] == ""


@pytest.mark.parametrize("provider", ["huawei_sa", "ransomwarelive"])
def test_providers_without_normalized_products_have_blank_affected(provider: str) -> None:
    template = review_template_from_document(
        document(provider, {"raw_sections": {"affected": "raw"}, "victim": "Company", "vul": [{"cveId": "x"}]})
    )

    assert template["affected"] == []


@pytest.mark.parametrize(
    ("provider", "detail", "severity", "affected"),
    [
        ("cisco", {"sir": "Critical", "product_names": ["IOS XE"]}, "Critical", "IOS XE"),
        (
            "fortiguard",
            {
                "severity": "High",
                "affected_products": [
                    {
                        "version": "FortiWeb 8.0",
                        "affected": "8.0.0 through 8.0.2",
                        "solution": "Upgrade to 8.0.3 or above",
                    },
                ],
            },
            "High",
            "FortiWeb 8.0 8.0.0 through 8.0.2",
        ),
        ("huawei_sa", {"severity": "High", "vul": [{"cveId": "CVE-1"}]}, "High", ""),
        ("paloalto", {"severity": "HIGH", "products": ["PAN-OS"]}, "High", "PAN-OS"),
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
        (
            "nvd",
            {
                "severity": "HIGH",
                "affected_products": [
                    "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*:*",
                    "cpe:2.3:a:vendor:product2:*:*:*:*:*:*:*:*:*",
                ],
            },
            "High",
            "cpe:2.3:a:vendor:product:1.0:*:*:*:*:*:*:*:*\ncpe:2.3:a:vendor:product2:*:*:*:*:*:*:*:*:*",
        ),
        (
            "cnnvd",
            {
                "hazardLevel": 2,
                "affectedProduct": "Chrome Desktop\r\nChromium",
                "affectedVendor": "Google",
            },
            "High",
            "Chrome Desktop\nChromium\nGoogle",
        ),
        ("cnvd", {"severity": "中", "affected_products": ["Product A"]}, "Medium", "Product A"),
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
        "fortiguard",
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
        "nvd",
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


def test_review_document_validation_rejects_mixed_mongodb_review_shapes() -> None:
    valid = {
        "title": "Title",
        "description": "",
        "impacts": "",
        "affected": ["Product"],
        "cve": "",
        "recommendation": "",
        "related_link": [],
    }

    assert _review_document_errors(valid) == []

    errors = _review_document_errors(
        {
            **valid,
            "description": ["Wrong array"],
            "affected": "Wrong scalar",
            "recommendation": None,
            "code": "legacy-field",
        }
    )

    assert "extra fields ['code']" in errors
    assert "description must be a string" in errors
    assert "affected must be an array of strings" in errors
    assert "recommendation must be a string" in errors
