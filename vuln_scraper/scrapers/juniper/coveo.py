"""Juniper Support Portal Coveo/Aura API helpers (no browser)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request

PORTAL = "https://supportportal.juniper.net"
FWUID = (
    "ZkJhOVpLN2NZQkJrd2NWd3pMcnFOdzJEa1N5enhOU3R5QWl2VzNveFZTbGcxMy4t"
    "MjE0NzQ4MzY0OC4xMzEwNzIwMA"
)
APCK = "JHt0aW1lc3RhbXB9MDAwMDAwMDAwMDBlbl9VUw"
SEARCH_HUB = "PublicKnowledgeArticlesQSProd"

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


def get_coveo_config(*, page_uri: str = "/s/global-search/@uri") -> dict:
    """Mirror Salesforce CEC_HeadlessController.getHeadlessConfiguration."""
    aura_context = {
        "mode": "PROD",
        "fwuid": FWUID,
        "app": "siteforce:communityApp",
        "loaded": {
            "APPLICATION@markup://siteforce:communityApp": "1547_6p-2GBd9IQWZ4UXs1Im3BQ"
        },
        "dn": [],
        "globals": {},
        "uad": True,
    }
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
    form = urllib.parse.urlencode(
        {
            "message": json.dumps(message),
            "aura.context": json.dumps(aura_context),
            "aura.pageURI": page_uri,
            "aura.token": "undefined",
        }
    )
    aura_url = f"{PORTAL}/s/sfsites/aura?r=1&apck={APCK}"
    raw = post_json(aura_url, form)
    action = raw["actions"][0]
    if action.get("state") != "SUCCESS":
        raise RuntimeError(f"Aura action failed: {action}")
    return json.loads(action["returnValue"])


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
