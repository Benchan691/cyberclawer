"""Aliyun AVD sigchl challenge: solve inline JS and fetch the redirect URL."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup

from vuln_scraper.scrapers.avd.config import LIST_URL

DEFAULT_LIST_URL = f"{LIST_URL}?page=1"

HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/124.0.0.0 Safari/537.36"
    ),
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
}

REQUEST_TIMEOUT = 20.0


class AVDSigchlError(Exception):
    """Raised when the sigchl redirect URL cannot be produced or fetched."""


def import_quickjs():
    try:
        import quickjs
    except ImportError as exc:
        raise ImportError(
            "quickjs is required for AVD sigchl bypass; install with: pip install -e '.[avd]'"
        ) from exc
    return quickjs


def build_js_prelude(url: str, user_agent: str) -> str:
    u = urlparse(url)
    protocol = f"{u.scheme}:"
    host = u.netloc
    hostname = u.hostname or ""
    port = str(u.port or "")
    pathname = u.path or "/"
    search = f"?{u.query}" if u.query else ""
    fragment = u.fragment or ""

    return f"""
var _redirected_href = null;
var location = {{
    href: {url!r},
    protocol: {protocol!r},
    host: {host!r},
    hostname: {hostname!r},
    port: {port!r},
    pathname: {pathname!r},
    search: {search!r},
    hash: {fragment!r},
    assign: function(h) {{ _redirected_href = h; }},
    replace: function(h) {{ _redirected_href = h; }}
}};
Object.defineProperty(location, 'href', {{
    get: function() {{ return _redirected_href || {url!r}; }},
    set: function(h) {{ _redirected_href = h; }}
}});
var _cookie = "";
var document = {{
    cookie: _cookie,
    location: location,
    createElement: function(tag) {{
        var obj = {{
            protocol: {protocol!r},
            host: {host!r},
            hostname: {hostname!r},
            port: {port!r},
            pathname: {pathname!r},
            search: {search!r},
            hash: {fragment!r},
            href: {url!r}
        }};
        obj.firstChild = Object.assign({{}}, obj);
        return obj;
    }},
    getElementById: function() {{ return null; }},
    getElementsByTagName: function() {{ return []; }},
    querySelector: function() {{ return null; }},
    querySelectorAll: function() {{ return []; }}
}};
var window = {{
    navigator: {{ userAgent: {user_agent!r} }},
    location: location,
    document: document
}};
var navigator = window.navigator;
function setTimeout(fn, t)  {{ try {{ fn(); }} catch(e) {{}} }}
function setInterval(fn, t) {{}}
function clearTimeout(id)   {{}}
function clearInterval(id)  {{}}
var console = {{
    log:   function() {{}},
    warn:  function() {{}},
    error: function() {{}}
}};
"""


def _run_inline_script(code: str, base_url: str, user_agent: str) -> str | None:
    quickjs = import_quickjs()
    ctx = quickjs.Context()
    ctx.eval(build_js_prelude(base_url, user_agent))
    ctx.eval(code)
    href = ctx.eval("_redirected_href")
    return href if isinstance(href, str) and href.strip() else None


def _iter_inline_scripts(html: str, page_url: str, session: requests.Session, headers: Mapping[str, str]):
    soup = BeautifulSoup(html, "lxml")
    for idx, tag in enumerate(soup.find_all("script"), start=1):
        src = (tag.get("src") or "").strip()
        if src:
            full_url = urljoin(page_url, src)
            try:
                resp = session.get(full_url, headers=headers, timeout=REQUEST_TIMEOUT)
                resp.raise_for_status()
                code = resp.text.strip()
                if code:
                    yield full_url, code
            except Exception:
                continue
            continue
        code = (tag.string or tag.get_text() or "").strip()
        if code:
            yield page_url, code


def solve_redirect_url(url: str, html: str, *, user_agent: str, headers: Mapping[str, str] | None = None) -> str:
    hdrs = dict(headers or HEADERS)
    with requests.Session() as session:
        for script_url, code in _iter_inline_scripts(html, url, session, hdrs):
            redirect = _run_inline_script(code, script_url, user_agent)
            if redirect:
                return redirect
    raise AVDSigchlError(f"no sigchl redirect URL produced for {url}")


def _cookies_from_session(session: requests.Session) -> list[dict[str, Any]]:
    cookies: list[dict[str, Any]] = []
    for cookie in session.cookies:
        cookies.append(
            {
                "name": cookie.name,
                "value": cookie.value,
                "domain": cookie.domain,
                "path": cookie.path or "/",
            }
        )
    return cookies


def _apply_cookies(session: requests.Session, cookies: list[dict[str, Any]] | None) -> None:
    if not cookies:
        return
    for cookie in cookies:
        name = cookie.get("name")
        value = cookie.get("value")
        if not name or value is None:
            continue
        session.cookies.set(
            name,
            value,
            domain=cookie.get("domain"),
            path=cookie.get("path") or "/",
        )


def fetch_via_redirect(
    url: str,
    *,
    headers: Mapping[str, str] | None = None,
    cookies: list[dict[str, Any]] | None = None,
) -> tuple[str, str, list[dict[str, Any]]]:
    """
    GET url (challenge), solve sigchl redirect, GET redirect URL.
    Returns (html, final_url, session_cookies).
    """
    hdrs = dict(headers or HEADERS)
    user_agent = hdrs.get("User-Agent") or HEADERS["User-Agent"]

    with requests.Session() as session:
        _apply_cookies(session, cookies)
        challenge = session.get(url, headers=hdrs, timeout=REQUEST_TIMEOUT)
        challenge.raise_for_status()
        redirect_url = solve_redirect_url(
            url,
            challenge.text,
            user_agent=user_agent,
            headers=hdrs,
        )
        cleared = session.get(redirect_url, headers=hdrs, timeout=REQUEST_TIMEOUT)
        cleared.raise_for_status()
        return cleared.text, str(cleared.url), _cookies_from_session(session)


def main() -> None:
    from vuln_scraper.scrapers.avd.parsers.list import parse_high_risk_list

    html, final_url, _cookies = fetch_via_redirect(DEFAULT_LIST_URL)
    page = parse_high_risk_list(html, page=1, provider="avd", source_url=DEFAULT_LIST_URL)
    print(f"cleared URL: {final_url}")
    print(f"entries: {len(page.entries)} (total_records={page.total_records})")


if __name__ == "__main__":
    main()
