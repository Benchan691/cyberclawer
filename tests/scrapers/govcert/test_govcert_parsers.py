from pathlib import Path

from vuln_scraper.scrapers.govcert.parsers.detail import parse_detail_page
from vuln_scraper.scrapers.govcert.parsers.list import parse_alerts_list


FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_alerts_list_extracts_identity_and_dates_from_rss() -> None:
    xml = (FIXTURES / "list.xml").read_text(encoding="utf-8")

    page = parse_alerts_list(
        xml,
        page=1,
        provider="govcert",
        source_url="https://www.govcert.gov.hk/en/alerts.php",
    )

    assert page.total_pages == 1
    assert page.total_records == len(page.entries) == 2
    entry = page.entries[0]
    assert entry.identity.type == "GOVCERT"
    assert entry.identity.code == "1894"
    assert entry.title == "High Threat Security Alert (A26-06-01): Vulnerability in Linux Kernel"
    assert entry.vuln_type == "A26-06-01"
    assert entry.disclosure_date == "2026-06-01"
    assert entry.status == "High Threat Security Alert"
    assert entry.embedded_detail == {
        "_list_summary": True,
        "alert_code": "A26-06-01",
        "alert_type": "High Threat Security Alert",
        "severity": "Critical",
        "published_date": "2026-06-01",
        "description": "Review security updates for the Linux kernel.",
        "detail_url": "https://www.govcert.gov.hk/en/alerts_detail.php?id=1894",
    }

    second = page.entries[1]
    assert second.identity.code == "1893"
    assert second.vuln_type == "A26-05-48"
    assert second.status == "Security Alert"
    assert second.disclosure_date == "2026-05-29"
    assert second.embedded_detail["severity"] == "Medium"


def test_parse_high_threat_detail_extracts_sections_tags_and_links() -> None:
    html = (FIXTURES / "detail_high_threat.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["alert_code"] == "A26-06-01"
    assert detail["alert_type"] == "High Threat Security Alert"
    assert detail["severity"] == "Critical"
    assert detail["published_date"] == "2026-06-01"
    assert detail["updated_date"] is None
    assert "CIFSwitch" in detail["description"]
    assert detail["affected_systems"] == [
        "Linux kernel version with the CIFS client capability and the cifs-utils package version 6.14 or high"
    ]
    assert "elevation of privilege" in detail["impact"]
    assert detail["recommendation"] == "System administrators should follow vendor recommendations."
    assert detail["more_information_links"] == ["https://github.com/manizada/CIFSwitch"]
    assert detail["tags"] == ["Linux", "kernel"]
    assert detail["cve_ids"] == []
    assert "description" in detail["raw_sections"]


def test_parse_multi_cve_detail_extracts_cve_ids_and_links() -> None:
    html = (FIXTURES / "detail_multi_cve.html").read_text(encoding="utf-8")

    detail = parse_detail_page(html).to_dict()

    assert detail["alert_code"] == "A26-05-48"
    assert detail["alert_type"] == "Security Alert"
    assert detail["severity"] == "Medium"
    assert detail["published_date"] == "2026-05-29"
    assert detail["cve_ids"] == ["CVE-2026-9872", "CVE-2026-10022"]
    assert detail["more_information_links"] == [
        "https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security#may-28-2026",
        "https://www.hkcert.org/security-bulletin/microsoft-edge-multiple-vulnerabilities_20260529",
        "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2026-9872",
    ]
    assert detail["tags"] == ["Microsoft", "Edge"]


def test_parse_detail_page_handles_missing_optional_sections() -> None:
    detail = parse_detail_page("<h1 id='doc_title'>Security Alert (A26-01-01): Test</h1>").to_dict()

    assert detail["alert_code"] == "A26-01-01"
    assert detail["alert_type"] == "Security Alert"
    assert detail["published_date"] is None
    assert detail["affected_systems"] == []
    assert detail["more_information_links"] == []
    assert detail["tags"] == []
    assert detail["raw_sections"] == {}


def test_parse_detail_page_accepts_current_h2_section_headings() -> None:
    detail = parse_detail_page("""
        <h1 id="doc_title">Security Alert (A26-07-29): Apache Tomcat</h1>
        <div class="noneditable">
          <h2>Description:</h2><p>A remote attacker could exploit the issue.</p>
          <h2>Affected Systems:</h2><ul><li>Apache Tomcat 9.0</li></ul>
          <h2>Recommendation:</h2><p>Install the update.</p>
        </div>
    """).to_dict()

    assert detail["description"] == "A remote attacker could exploit the issue."
    assert detail["affected_systems"] == ["Apache Tomcat 9.0"]
    assert detail["recommendation"] == "Install the update."


def test_feed_accepts_guid_fallback_and_skips_duplicate_or_invalid_alerts() -> None:
    page = parse_alerts_list("""
        <rss xmlns="urn:test:rss"><channel>
          <item><title>High Threat Security Alert (A26-10-36): PHP</title>
            <guid>https://www.govcert.gov.hk/en/alerts_detail.php?id=2125</guid>
            <pubDate>Wed, 21 Oct 2026 12:00:00 +0800</pubDate></item>
          <item><title>Duplicate</title><link>alerts_detail.php?id=2125</link></item>
          <item><title>Other site</title><link>https://other.test/en/alerts_detail.php?id=9999</link></item>
          <item><title>Other language</title><link>/tc/alerts_detail.php?id=9998</link></item>
          <item><title>Invalid ID</title><link>alerts_detail.php?id=bad</link></item>
          <item><title>Missing ID</title><link>alerts_detail.php</link></item>
          <item><title> </title><link>alerts_detail.php?id=9997</link></item>
        </channel></rss>
    """, page=1)

    assert [entry.identity.code for entry in page.entries] == ["2125"]
    assert page.entries[0].disclosure_date == "2026-10-21"


def test_current_detail_preserves_full_body_references_and_tables() -> None:
    detail = parse_detail_page((FIXTURES / "detail.html").read_text(encoding="utf-8")).to_dict()

    assert detail["alert_code"] == "A26-10-36"
    assert detail["published_date"] == "2026-10-21"
    assert detail["cve_ids"] == ["CVE-2026-109618", "CVE-2026-109619"]
    assert detail["affected_systems"] == ["PHP frameworks and applications"]
    assert "Administrators should prepare" in detail["description"]
    assert "Check all internet-facing applications" in detail["content"]
    assert "Unrelated site navigation" not in detail["content"]
    assert "Unrelated global tag list" not in detail["content"]
    assert detail["tags"] == ["PHP"]
    assert detail["tables"] == [[["Product", "Action"], ["PHP", "Apply security updates"]]]
    assert "https://www.php.net/archive/2026.php" in detail["reference_links"]
    assert "https://www.php.net/security" in detail["reference_links"]
