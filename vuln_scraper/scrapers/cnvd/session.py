"""CNVD gate session: JSL 521 clearance + captcha OCR, cookie persistence."""

from __future__ import annotations

import base64
import itertools
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from vuln_scraper.scrapers.cnvd.config import BASE_URL

logger = logging.getLogger(__name__)

CAPTCHA_PATH = "/cdn-cgi/captcha/v2/captcha/image"
DEFAULT_COOKIE_FILENAME = "cnvd_session_cookies.json"
MAX_RETRIES = 50
RETRY_DELAY = 0.3
REQUEST_TIMEOUT = 15.0

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/148.0.0.0 Safari/537.36 Edg/148.0.0.0"
)
_SEC_CH_UA = '"Chromium";v="148", "Microsoft Edge";v="148", "Not/A)Brand";v="99"'

_HDR_NAVIGATE = {
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,"
        "image/avif,image/webp,image/apng,*/*;q=0.8,"
        "application/signed-exchange;v=b3;q=0.7"
    ),
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
    "Priority": "u=0, i",
    "sec-ch-ua": _SEC_CH_UA,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
}

_HDR_XHR = {
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Priority": "u=1, i",
    "Referer": f"{BASE_URL}/",
    "sec-ch-ua": _SEC_CH_UA,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "Sec-Fetch-Dest": "empty",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Site": "same-origin",
}

CNVD_REQUEST_HEADERS = {
    "User-Agent": USER_AGENT,
    **_HDR_NAVIGATE,
}

_captcha_counter = itertools.count(1)
_CJK_RE = re.compile(r"^[\u4e00-\u9fff]{2}$")

_CNVD_EXTRA_HINT = (
    "CNVD session requires optional dependencies. Install with: pip install -e '.[cnvd]'"
)


class CNVDSessionError(Exception):
    """Raised when CNVD gate authentication fails."""


def default_cookie_path(data_dir: Path) -> Path:
    return Path(data_dir) / DEFAULT_COOKIE_FILENAME


def _import_cnvd_deps() -> tuple[Any, Any, Any]:
    try:
        import ddddocr
        import quickjs
        import requests
    except ImportError as exc:
        raise CNVDSessionError(_CNVD_EXTRA_HINT) from exc
    return ddddocr, quickjs, requests


def save_cookies(session: Any, path: Path) -> None:
    data = {
        c.name: {
            "value": c.value,
            "domain": c.domain,
            "path": c.path,
            "expires": c.expires,
            "secure": c.secure,
        }
        for c in session.cookies
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    logger.info("CNVD cookies saved to %s (%d)", path, len(data))


def load_cookies(session: Any, path: Path) -> None:
    if not path.exists():
        logger.debug("CNVD cookie file not found: %s", path)
        return
    for name, attrs in json.loads(path.read_text(encoding="utf-8")).items():
        session.cookies.set(name, attrs["value"], domain=attrs["domain"])
    logger.info("Loaded %d CNVD cookies from %s", len(session.cookies), path)


def solve_jsl(session: Any, html: str, ctx: Any) -> bool:
    match = re.search(r"document\.cookie=(.+?);location", html)
    if not match:
        logger.warning("JSL challenge script not found in response")
        return False

    expr = match.group(1)
    cookie_str = str(ctx.eval(expr))
    name_val = cookie_str.split(";")[0].strip()
    name, value = name_val.split("=", 1)
    session.cookies.set(name.strip(), value.strip(), domain="www.cnvd.org.cn")
    return True


@dataclass
class CaptchaResult:
    sec: str
    image_bytes: bytes = field(repr=False)


def visit(session: Any, ctx: Any) -> Any:
    logger.info("CNVD session: GET %s", BASE_URL)
    response = session.get(BASE_URL, headers=_HDR_NAVIGATE, timeout=REQUEST_TIMEOUT)

    if response.status_code == 521:
        logger.info("CNVD session: solving JSL 521 challenge")
        solve_jsl(session, response.text, ctx)
        response = session.get(BASE_URL, headers=_HDR_NAVIGATE, timeout=REQUEST_TIMEOUT)

    if response.status_code not in (200, 521):
        response.raise_for_status()
    return response


def get_captcha(session: Any, ctx: Any) -> CaptchaResult:
    counter = next(_captcha_counter)
    random_s = str(ctx.eval("Math.random().toString(24).substring(8, 24)"))
    url = f"{BASE_URL}{CAPTCHA_PATH}?c={counter}&s={random_s}"
    response = session.get(url, headers=_HDR_XHR, timeout=REQUEST_TIMEOUT)
    response.raise_for_status()
    data = response.json()
    return CaptchaResult(sec=data["sec"], image_bytes=base64.b64decode(data["image"]))


def is_two_cjk(text: str) -> bool:
    return bool(_CJK_RE.match(text.strip()))


def ocr_classify(ocr: Any, image_bytes: bytes) -> str:
    return ocr.classification(image_bytes, png_fix=True).strip()


def submit_captcha(session: Any, captcha: CaptchaResult, answer: str) -> None:
    url = f"{BASE_URL}{CAPTCHA_PATH}"
    response = session.post(
        url,
        data={"ans": answer, "sec": captcha.sec},
        headers={
            **_HDR_XHR,
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": BASE_URL,
        },
        timeout=REQUEST_TIMEOUT,
    )
    if response.status_code == 200:
        return

    try:
        message = response.json().get("msg", "").encode("latin-1").decode("gbk")
    except Exception:
        message = response.text[:120]
    raise RuntimeError(f"HTTP {response.status_code}: {message}")


def cookies_from_requests_session(session: Any) -> list[dict[str, Any]]:
    return [
        {
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain,
            "path": cookie.path or "/",
        }
        for cookie in session.cookies
        if cookie.name and cookie.value is not None
    ]


@dataclass
class CNVDSession:
    cookie_path: Path | None = None
    max_retries: int = MAX_RETRIES
    retry_delay: float = RETRY_DELAY
    _cookies: list[dict[str, Any]] = field(default_factory=list, repr=False)

    @classmethod
    def for_data_dir(
        cls,
        data_dir: Path,
        *,
        cookie_path: Path | None = None,
        max_retries: int = MAX_RETRIES,
        retry_delay: float = RETRY_DELAY,
    ) -> CNVDSession:
        del data_dir
        return cls(
            cookie_path=cookie_path,
            max_retries=max_retries,
            retry_delay=retry_delay,
        )

    @property
    def is_authenticated(self) -> bool:
        return bool(self._cookies)

    def ensure_authenticated(
        self,
        *,
        refresh_cookies: bool = True,
        persist_cookies: bool = False,
    ) -> None:
        """Authenticate with CNVD and store cookies in memory for httpx injection."""
        if refresh_cookies:
            self._cookies = []
            if self.cookie_path is not None and self.cookie_path.exists():
                self.cookie_path.unlink()
                logger.info("Cleared stale CNVD cookies at %s", self.cookie_path)

        ddddocr_mod, quickjs_mod, requests_mod = _import_cnvd_deps()
        ocr = ddddocr_mod.DdddOcr(beta=True, show_ad=False)
        ctx = quickjs_mod.Context()

        with requests_mod.Session() as session:
            session.headers.update({"User-Agent": USER_AGENT})
            if not refresh_cookies and self.cookie_path is not None:
                load_cookies(session, self.cookie_path)
            visit(session, ctx)

            for attempt in range(1, self.max_retries + 1):
                logger.info("CNVD captcha attempt %d/%d", attempt, self.max_retries)
                try:
                    captcha = get_captcha(session, ctx)
                except Exception as exc:
                    logger.warning("CNVD captcha fetch failed: %s", exc)
                    time.sleep(self.retry_delay)
                    continue

                answer = ocr_classify(ocr, captcha.image_bytes)
                if not is_two_cjk(answer):
                    logger.debug("CNVD OCR skipped (not two CJK): %r", answer)
                    time.sleep(self.retry_delay)
                    continue

                try:
                    submit_captcha(session, captcha, answer)
                except RuntimeError as exc:
                    logger.warning("CNVD captcha submit failed: %s", exc)
                    time.sleep(self.retry_delay)
                    continue

                self._cookies = cookies_from_requests_session(session)
                if persist_cookies and self.cookie_path is not None:
                    save_cookies(session, self.cookie_path)
                verify = session.get(BASE_URL, headers=_HDR_NAVIGATE, timeout=REQUEST_TIMEOUT)
                if verify.status_code not in (200, 521):
                    verify.raise_for_status()
                logger.info(
                    "CNVD session authenticated (%d cookies%s)",
                    len(self._cookies),
                    f", saved to {self.cookie_path}" if persist_cookies and self.cookie_path else "",
                )
                return

        raise CNVDSessionError(
            f"CNVD captcha bypass failed after {self.max_retries} attempts"
        )

    def cookies_for_httpx(self) -> list[dict[str, Any]]:
        return list(self._cookies)
