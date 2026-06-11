import pytest

from vuln_scraper.models import ListEntry, VulnerabilityId, normalize_cve_code, primary_cve_code


def test_primary_cve_code_reads_raw_camel_case_code() -> None:
    assert primary_cve_code({"cveCode": "CVE-2026-11628"}) == "2026-11628"


def test_vulnerability_id_parses_type_and_code() -> None:
    identity = VulnerabilityId.parse("CVE-2026-42945")

    assert identity.type == "CVE"
    assert identity.code == "2026-42945"
    assert identity.key == "CVE:2026-42945"
    assert identity.display == "CVE-2026-42945"


def test_vulnerability_id_rejects_malformed_value() -> None:
    with pytest.raises(ValueError):
        VulnerabilityId.parse("2026-42945")


def test_normalize_cve_code_accepts_prefixed_and_bare_values() -> None:
    assert normalize_cve_code("CVE-2025-48595") == "2025-48595"
    assert normalize_cve_code("2025-48595") == "2025-48595"
    assert normalize_cve_code("not-a-cve") is None


def test_primary_cve_code_uses_first_detail_identifier() -> None:
    assert (
        primary_cve_code(
            {
                "vulnerability_identifiers": [
                    {"cve_id": "CVE-2025-48595"},
                    {"cve_id": "CVE-2025-48633"},
                ]
            }
        )
        == "2025-48595"
    )


def test_list_entry_builds_cve_code_from_vulnerability_identifiers() -> None:
    entry = ListEntry(
        identity=VulnerabilityId(type="HKCERT", code="android-multiple-vulnerabilities_20250601"),
        title="Android Multiple Vulnerabilities",
        vuln_type=None,
        disclosure_date="1 Jun 2025",
        status="NEW",
        provider="hkcert",
        source_url="https://www.hkcert.org/security-bulletin",
    )

    record = entry.to_record(
        {
            "vulnerability_identifiers": [
                {"cve_id": "CVE-2025-48595"},
                {"cve_id": "CVE-2025-48595"},
            ]
        },
        detail_url="https://www.hkcert.org/security-bulletin/android-multiple-vulnerabilities_20250601",
    )

    assert record["type"] == "hkcert"
    assert record["cve_code"] == "2025-48595"
    assert "cross_refs" not in record
    assert "hkcert" in record["details"]
