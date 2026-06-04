import pytest

from vuln_scraper.filters import (
    parse_attribute_filter,
    record_has_cve,
    record_matches_attribute_filters,
    record_matches_types,
)


def test_cve_classification_from_title() -> None:
    record = {"title": "Example issue (CVE-2026-12345)", "cve_code": "2026-12345", "details": {}}

    assert record_has_cve(record)
    assert record_matches_types(record, include_cve=True, include_non_cve=False)
    assert not record_matches_types(record, include_cve=False, include_non_cve=True)


def test_cve_classification_from_detail() -> None:
    record = {
        "title": "Vendor advisory",
        "cve_code": "2026-99999",
    }

    assert record_has_cve(record)


def test_non_cve_classification() -> None:
    record = {"title": "Supply chain poisoning event", "cve_code": None, "details": {"avd": {}}}

    assert not record_has_cve(record)
    assert record_matches_types(record, include_cve=False, include_non_cve=True)


def test_attribute_filters_match_top_level_and_aliases() -> None:
    record = {
        "type": "avd",
        "code": "2026-10001",
        "status": "CVE PoC",
        "cve_code": "2026-10001",
    }

    assert record_matches_attribute_filters(record, [("type", "avd")])
    assert record_matches_attribute_filters(record, [("code", "2026-10001")])
    assert record_matches_attribute_filters(record, [("cve_code", "2026-10001")])
    assert record_matches_attribute_filters(record, [("status", "poc")])


def test_attribute_filters_match_nested_arrays() -> None:
    record = {
        "details": {
            "avd": {
                "affected_software": [
                    {"vendor": "ubuntu_24.04", "product": "nginx", "version": "*"},
                    {"vendor": "redhat_9", "product": "openssl", "version": "*"},
                ],
                "reference_links": ["https://example.test/advisory"],
            }
        }
    }

    assert record_matches_attribute_filters(record, [("details.avd.affected_software.product", "NGINX")])
    assert record_matches_attribute_filters(record, [("details.avd.reference_links", "advisory")])


def test_attribute_filters_combine_with_and() -> None:
    record = {"status": "CVE PoC", "details": {"avd": {"danger_level": "高危"}}}

    assert record_matches_attribute_filters(record, [("status", "poc"), ("details.avd.danger_level", "高危")])
    assert not record_matches_attribute_filters(
        record,
        [("status", "poc"), ("details.avd.patch_status", "official")],
    )


def test_parse_attribute_filter_rejects_invalid_syntax() -> None:
    with pytest.raises(ValueError):
        parse_attribute_filter("status")
