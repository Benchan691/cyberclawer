from __future__ import annotations

from typing import Any, Literal, Protocol

from vuln_scraper.models import ListPage
from vuln_scraper.scrapers.avd import AVDProvider
from vuln_scraper.scrapers.cisco import CiscoProvider
from vuln_scraper.scrapers.cnnvd import CNNVDProvider
from vuln_scraper.scrapers.cnvd import CNVDProvider
from vuln_scraper.scrapers.cve import CVEProvider
from vuln_scraper.scrapers.govcert import GovCERTProvider
from vuln_scraper.scrapers.github_advisory import GitHubAdvisoryProvider
from vuln_scraper.scrapers.hikvision import HikvisionProvider
from vuln_scraper.scrapers.hkcert import HKCERTProvider
from vuln_scraper.scrapers.huawei_sa import HuaweiSAProvider
from vuln_scraper.scrapers.infosec import InfoSecProvider
from vuln_scraper.scrapers.juniper import JuniperProvider
from vuln_scraper.scrapers.paloalto import PaloAltoProvider
from vuln_scraper.scrapers.qianxin import QianxinProvider
from vuln_scraper.scrapers.ransomwarelive import RansomwareLiveProvider
from vuln_scraper.scrapers.splunk import SplunkProvider
from vuln_scraper.scrapers.zeroday import ZeroDayProvider


class ScraperProvider(Protocol):
    key: str
    source_url: str
    default_mongo_collection: str
    browser_fallback: bool
    content_type: Literal["html", "json"]
    default_request_delay: float
    stop_on_first_known: bool

    def list_url(self, page: int, *, checkpoint: object | None = None) -> str: ...

    def detail_url(self, identity_display: str) -> str: ...

    def parse_list(self, content: Any, *, page: int) -> ListPage: ...

    def parse_detail(self, content: Any) -> Any: ...


PROVIDERS: dict[str, type[ScraperProvider]] = {
    "avd": AVDProvider,
    "hkcert": HKCERTProvider,
    "cve": CVEProvider,
    "cisco": CiscoProvider,
    "zeroday": ZeroDayProvider,
    "govcert": GovCERTProvider,
    "github_advisory": GitHubAdvisoryProvider,
    "huawei_sa": HuaweiSAProvider,
    "paloalto": PaloAltoProvider,
    "qianxin": QianxinProvider,
    "ransomwarelive": RansomwareLiveProvider,
    "infosec": InfoSecProvider,
    "splunk": SplunkProvider,
    "hikvision": HikvisionProvider,
    "cnnvd": CNNVDProvider,
    "cnvd": CNVDProvider,
    "juniper": JuniperProvider,
}


def provider_keys() -> tuple[str, ...]:
    return tuple(sorted(PROVIDERS))


def get_provider(key: str) -> ScraperProvider:
    factory = PROVIDERS.get(key)
    if factory is None:
        choices = ", ".join(sorted(PROVIDERS))
        raise KeyError(f"unknown provider {key!r}; choose one of: {choices}")
    return factory()


def all_providers() -> list[ScraperProvider]:
    return [factory() for factory in PROVIDERS.values()]
