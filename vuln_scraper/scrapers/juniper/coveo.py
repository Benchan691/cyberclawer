"""Juniper Support Portal Coveo/Aura API helpers (no browser)."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from html import unescape

from bs4 import BeautifulSoup

from vuln_scraper.client import FetchError, ScraperClient

PORTAL = "https://supportportal.juniper.net"
SEARCH_HUB = "PublicKnowledgeArticlesQSProd"
CONTEXT_OBJECT_RE = re.compile(r'\{\s*"(?:context|mode|fwuid|app|loaded)"\s*:')

DEFAULT_FACETS = [
    {"field": "@primarysourcename", "values": ["Knowledge"]},
    {"field": "@articletype", "values": ["Security Advisories"]},
]

ARTICLE_RAW_FIELDS = [
    "sfcec_documentid__c",
    "sftitle",
    "sfurlname",
    "sfrecordtypename",
    "sfcec_severity_level__c",
    "sfcec_severity_assessment__c",
    "sfcec_cvss_score__c",
    "sfcec_problem__c",
    "sfcec_product_affected__c",
    "sfcec_solution__c",
    "sfcec_workaround__c",
    "sfcec_modification_history__c",
    "sfcec_related_links__c",
    "sfcustomer_url__c",
    "sflastpublisheddate",
    "sflastmodifieddate",
    "sfdatacategoryknowledge_articles",
]


def post_json(url: str, payload: dict | str, headers: dict | None = None) -> dict:
    if isinstance(payload, dict):
        body = json.dumps(payload).encode()
        hdrs = {"Content-Type": "application/json", "Accept": "application/json"}
    else:
        body = payload.encode() if isinstance(payload, str) else payload
        hdrs = {"Content-Type": "application/x-www-form-urlencoded; charset=UTF-8"}
    hdrs = {"User-Agent": "Mozilla/5.0", **(headers or {}), **hdrs}
    req = urllib.request.Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=60) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode(errors="replace")[:800]
        raise RuntimeError(f"HTTP {exc.code} for {url}: {detail}") from exc


def _aura_context(html: str) -> dict:
    """Read the live Aura context from inline JSON or encoded resource URLs."""
    parsed = BeautifulSoup(html, "lxml")
    sources = [unescape(html)]
    for tag in parsed.find_all(("script", "link")):
        url = tag.get("src") or tag.get("href")
        if url:
            sources.append(urllib.parse.unquote(unescape(str(url))))

    decoder = json.JSONDecoder()
    for source in sources:
        for match in CONTEXT_OBJECT_RE.finditer(source):
            try:
                value, _ = decoder.raw_decode(source, match.start())
            except ValueError:
                continue
            context = value.get("context", value)
            if not isinstance(context, dict):
                continue
            if not all(isinstance(context.get(key), str) and context[key] for key in ("mode", "fwuid", "app")):
                continue
            if not isinstance(context.get("loaded"), dict):
                continue
            return {
                "mode": context["mode"],
                "fwuid": context["fwuid"],
                "app": context["app"],
                "loaded": context["loaded"],
                "dn": context.get("dn", []),
                "globals": context.get("globals", {}),
                "uad": context.get("uad", True),
            }
    raise FetchError("Juniper portal did not contain an Aura framework context")


def _configuration(payload: object) -> dict:
    actions = payload.get("actions") if isinstance(payload, dict) else None
    if not isinstance(actions, list) or not actions or not isinstance(actions[0], dict):
        raise FetchError("Juniper Aura bootstrap did not return a configuration action")
    action = actions[0]
    if action.get("state") != "SUCCESS":
        raise FetchError(f"Juniper Aura bootstrap failed (state={action.get('state')})")
    value = action.get("returnValue")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError as exc:
            raise FetchError("Juniper Aura bootstrap returned invalid configuration JSON") from exc
    if not isinstance(value, dict) or not all(
        isinstance(value.get(key), str) and value[key].strip()
        for key in ("organizationId", "accessToken")
    ):
        raise FetchError("Juniper Aura configuration is missing organizationId or accessToken")
    return value


async def get_coveo_config(client: ScraperClient, *, page_uri: str = "/s/global-search/@uri") -> dict:
    """Bootstrap through the shared HTTP session, including retries and cookies."""
    message = {
        "actions": [
            {
                "id": "1;a",
                "descriptor": "apex://CEC_HeadlessController/ACTION$getHeadlessConfiguration",
                "callingDescriptor": "UNKNOWN",
                "params": {},
            }
        ]
    }
    for attempt in range(2):
        page = await client.get_html(f"{PORTAL}{page_uri}")
        form = {
            "message": json.dumps(message),
            "aura.context": json.dumps(_aura_context(page.html)),
            "aura.pageURI": page_uri,
            "aura.token": "undefined",
        }
        result = await client.request_json(
            "POST",
            f"{PORTAL}/s/sfsites/aura?r=1",
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded; charset=UTF-8",
                "Referer": page.url,
            },
            data=form,
        )
        # A deployment between the page GET and action POST invalidates fwuid.
        if "clientoutofsync" in json.dumps(result.data).casefold():
            if attempt == 0:
                continue
            raise FetchError("Juniper Aura framework remained out of sync")
        return _configuration(result.data)


def coveo_search_url(cfg: dict) -> str:
    org = cfg["organizationId"]
    return f"https://{org}.org.coveo.com/rest/search/v2?organizationId={org}"


def coveo_search_body(
    *,
    q: str = "",
    first_result: int = 0,
    number_of_results: int = 25,
    facet_filters: list[dict] | None = None,
    fields_to_include: list[str] | None = None,
    sort_criteria: str | None = None,
) -> dict:
    body: dict = {
        "q": q,
        "searchHub": SEARCH_HUB,
        "numberOfResults": number_of_results,
        "firstResult": first_result,
        "locale": "en-US",
    }
    if facet_filters:
        body["facetFilters"] = facet_filters
    if fields_to_include:
        body["fieldsToInclude"] = fields_to_include
    if sort_criteria:
        body["sortCriteria"] = sort_criteria
    return body


def coveo_search(
    cfg: dict,
    *,
    q: str = "",
    first_result: int = 0,
    number_of_results: int = 25,
    facet_filters: list[dict] | None = None,
    fields_to_include: list[str] | None = None,
) -> dict:
    body = coveo_search_body(
        q=q,
        first_result=first_result,
        number_of_results=number_of_results,
        facet_filters=facet_filters,
        fields_to_include=fields_to_include,
    )
    return post_json(
        coveo_search_url(cfg),
        body,
        headers={"Authorization": f"Bearer {cfg['accessToken']}"},
    )


def search_by_slug(cfg: dict, slug: str) -> dict:
    body = coveo_search_body(q=f'@sfurlname=="{slug}"', number_of_results=1, fields_to_include=ARTICLE_RAW_FIELDS)
    payload = post_json(
        coveo_search_url(cfg),
        body,
        headers={"Authorization": f"Bearer {cfg['accessToken']}"},
    )
    results = payload.get("results") or []
    if not results:
        body["q"] = slug
        payload = post_json(
            coveo_search_url(cfg),
            body,
            headers={"Authorization": f"Bearer {cfg['accessToken']}"},
        )
        results = payload.get("results") or []
    if not results:
        raise LookupError(f"No Coveo document for slug: {slug}")
    return results[0]
