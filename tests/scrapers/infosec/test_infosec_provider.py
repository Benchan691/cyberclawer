from datetime import datetime
from zoneinfo import ZoneInfo

from vuln_scraper.scrapers import InfoSecProvider, get_provider, provider_keys


def test_infosec_provider_urls_and_registry() -> None:
    provider = InfoSecProvider()
    current_year = datetime.now(ZoneInfo("Asia/Hong_Kong")).year

    assert "infosec" in provider_keys()
    assert get_provider("infosec").key == "infosec"
    assert (
        provider.list_url(1)
        == f"https://www.infosec.gov.hk/en/news-events/security-alerts-and-advisories/{current_year}"
    )
    assert (
        provider.list_url(2)
        == f"https://www.infosec.gov.hk/en/news-events/security-alerts-and-advisories/{current_year - 1}"
    )
    assert (
        provider.detail_url("INFOSEC-1893")
        == "https://www.govcert.gov.hk/en/alerts_detail.php?id=1893"
    )
    assert provider.default_mongo_collection == "infosec"
    assert not provider.browser_fallback
    assert provider.stop_on_first_known


def test_infosec_provider_finalize_detail_merges_list_context() -> None:
    provider = InfoSecProvider()
    entry = provider.parse_list(
        """
        <div class="listing">
          <div class="newsrow alert">
            <div class="newsdate"><div>2026-5-29</div></div>
            <a href="https://www.govcert.gov.hk/en/alerts_detail.php?id=1893">
              <div class="newstitle">Security Alert (A26-05-48): Multiple Vulnerabilities in Microsoft Edge</div>
            </a>
            <div class="newscontent">List summary.</div>
          </div>
        </div>
        """,
        page=1,
    ).entries[0]

    detail = provider.finalize_detail(
        {"summary": None, "description": "Detail."},
        entry=entry,
        detail_url="https://www.govcert.gov.hk/en/alerts_detail.php?id=1893",
    )

    assert detail["summary"] == "List summary."
    assert detail["govcert_detail_url"] == "https://www.govcert.gov.hk/en/alerts_detail.php?id=1893"
