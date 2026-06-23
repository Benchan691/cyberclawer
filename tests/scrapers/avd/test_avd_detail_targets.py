from vuln_scraper.config import default_scrape_settings
from vuln_scraper.models import ListEntry, VulnerabilityId
from vuln_scraper.scrapers import get_provider
from vuln_scraper.runner import ScraperRunner


def test_avd_list_summary_is_not_treated_as_full_detail() -> None:
    settings = default_scrape_settings(limit=1)
    runner = ScraperRunner(settings, provider=get_provider("avd"))
    entry = ListEntry(
        identity=VulnerabilityId(type="AVD", code="2026-42588"),
        title="Apache ActiveMQ jolokia 代码执行漏洞（CVE-2026-42588）",
        vuln_type="CWE-20",
        disclosure_date="2026-06-01",
        status="CVE PoC",
        provider="avd",
        embedded_detail={
            "_list_summary": True,
            "reference_links": ["https://avd.aliyun.com/detail?id=AVD-2026-42588"],
        },
    )

    runner._merge_list_entries([entry])

    assert runner._has_detail(entry.key) is False
    targets = runner._detail_targets_for_page([entry], selected_count=0)
    assert [item.key for item in targets] == [entry.key]
