from __future__ import annotations

import pytest

from vuln_scraper.severity import normalize_severity, severity_from_record


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (1, "Critical"),
        (2, "High"),
        (3, "Medium"),
        (4, "Low"),
        ("超危", "Critical"),
        ("高危", "High"),
        ("中危", "Medium"),
        ("低危", "Low"),
        ("高", "High"),
        ("中", "Medium"),
        ("低", "Low"),
        ("CRITICAL", "Critical"),
        ("High", "High"),
        ("MEDIUM", "Medium"),
        ("moderate", "Medium"),
        ("LOW", "Low"),
        ("", None),
        (None, None),
        ("not-a-severity-label", "Unknown"),
    ],
)
def test_normalize_severity_maps_known_values(value: object, expected: str | None) -> None:
    assert normalize_severity(value) == expected


def test_severity_from_record_cnnvd_uses_hazard_level() -> None:
    record = {
        "type": "cnnvd",
        "status": "高危",
        "details": {
            "cnnvd": {
                "hazardLevel": 2,
                "vulName": "Example",
            }
        },
    }

    assert severity_from_record(record) == "High"


def test_severity_from_record_cnvd_prefers_document_status() -> None:
    record = {
        "type": "cnvd",
        "status": "中",
        "details": {"cnvd": {"severity": "低"}},
    }

    assert severity_from_record(record) == "Medium"


def test_severity_from_record_cve_uses_cvss_severity() -> None:
    record = {
        "type": "cve",
        "details": {
            "cve": {
                "metrics": {
                    "cvss_v31": [{"cvssData": {"baseSeverity": "HIGH"}}],
                }
            }
        },
    }

    assert severity_from_record(record) == "High"


def test_severity_from_record_hikvision() -> None:
    record = {
        "type": "hikvision",
        "details": {"hikvision": {"severity": "High"}},
    }

    assert severity_from_record(record) == "High"


def test_severity_from_record_msrc_uses_cvss_when_threat_is_not_severity() -> None:
    record = {
        "type": "msrc",
        "details": {
            "msrc": {
                "threats": [{"description": "Elevation of Privilege"}],
                "cvss": [{"base_score": "9.8"}],
            }
        },
    }

    assert severity_from_record(record) == "Critical"


def test_severity_from_record_msrc_uses_microsoft_severity_threat() -> None:
    record = {
        "type": "msrc",
        "details": {
            "msrc": {
                "threats": [
                    {"description": "Remote Code Execution"},
                    {"description": "Important"},
                ],
                "cvss": [{"base_score": "9.8"}],
            }
        },
    }

    assert severity_from_record(record) == "High"
