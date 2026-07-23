from datetime import datetime, timezone

import pytest

from vuln_scraper.schema_v2 import (
    PROHIBITED_FIELDS,
    PROVIDER_SCHEMAS,
    build_v2_document,
    mongo_json_schema,
    validate_v2_document,
)


@pytest.mark.parametrize("provider", sorted(PROVIDER_SCHEMAS))
def test_every_provider_builds_a_valid_deterministic_v2_document(provider: str) -> None:
    record = {
        "type": provider,
        "code": "2026-1000" if provider == "cve" else "native-code",
        "title": "Display title",
        "cve_codes": ["2026-1000", "CVE-2026-1000"],
        "status": "NEW",
        "details": {
            provider: {
                "description": "Provider evidence",
                "empty": "",
                "empty_list": [],
                "empty_object": {},
                "false_value": False,
                "zero_value": 0,
            }
        },
    }
    output = {"scraped_at": "2026-07-23T01:02:03Z"}

    first = build_v2_document(record, output)
    second = build_v2_document(record, output)

    assert first == second
    validate_v2_document(first, provider)
    assert not PROHIBITED_FIELDS.intersection(first)
    assert first["details"] == {
        "description": "Provider evidence",
        "false_value": False,
        "zero_value": 0,
    }
    assert first["change_type"] == "new"
    assert first["observed_at"] == datetime(2026, 7, 23, 1, 2, 3, tzinfo=timezone.utc)
    if provider == "cve":
        assert "cve_ids" not in first
    else:
        assert first["cve_ids"] == ["CVE-2026-1000"]


def test_validator_is_closed_and_classification_is_cve_only() -> None:
    avd_properties = mongo_json_schema("avd")["properties"]
    cve_properties = mongo_json_schema("cve")["properties"]

    assert mongo_json_schema("avd")["additionalProperties"] is False
    assert "classification" not in avd_properties
    assert "cve_ids" in avd_properties
    assert "classification" in cve_properties
    assert "cve_ids" not in cve_properties


def test_invalid_observed_at_and_duplicate_cves_are_rejected() -> None:
    with pytest.raises(ValueError):
        build_v2_document(
            {"type": "avd", "code": "x", "title": "x", "details": {}},
            {"scraped_at": "not-a-date"},
        )

    document = build_v2_document(
        {"type": "avd", "code": "x", "title": "x", "details": {}},
        {"scraped_at": "2026-01-01T00:00:00Z"},
    )
    document["cve_ids"] = ["CVE-2026-1000", "CVE-2026-1000"]
    with pytest.raises(ValueError):
        validate_v2_document(document, "avd")
