import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from vuln_scraper.scrapers.cnvd.session import (
    CNVDSession,
    CNVDSessionError,
    CaptchaResult,
    default_cookie_path,
    is_two_cjk,
    load_cookies,
    save_cookies,
    solve_jsl,
    submit_captcha,
)


def test_default_cookie_path(tmp_path: Path) -> None:
    assert default_cookie_path(tmp_path) == tmp_path / "cnvd_session_cookies.json"


def test_is_two_cjk() -> None:
    assert is_two_cjk("地球")
    assert not is_two_cjk("abc")
    assert not is_two_cjk("地球x")


def test_save_and_load_cookies(tmp_path: Path) -> None:
    session = MagicMock()
    cookie = MagicMock()
    cookie.name = "__jsluid_s"
    cookie.value = "abc"
    cookie.domain = "www.cnvd.org.cn"
    cookie.path = "/"
    cookie.expires = None
    cookie.secure = True
    session.cookies = [cookie]

    path = tmp_path / "cookies.json"
    save_cookies(session, path)
    loaded = MagicMock()
    load_cookies(loaded, path)
    loaded.cookies.set.assert_called_once_with("__jsluid_s", "abc", domain="www.cnvd.org.cn")


def test_solve_jsl_injects_cookie() -> None:
    session = MagicMock()
    ctx = MagicMock()
    ctx.eval.return_value = "__jsl_clearance_s=testvalue; Max-Age=3600"
    html = '<script>document.cookie=("a")+("b");location.href="/";</script>'

    assert solve_jsl(session, html, ctx) is True
    session.cookies.set.assert_called_once_with(
        "__jsl_clearance_s",
        "testvalue",
        domain="www.cnvd.org.cn",
    )


def test_submit_captcha_success() -> None:
    session = MagicMock()
    response = MagicMock(status_code=200)
    session.post.return_value = response
    captcha = CaptchaResult(sec="sec123", image_bytes=b"png")

    submit_captcha(session, captcha, "地球")
    session.post.assert_called_once()


def test_submit_captcha_failure() -> None:
    session = MagicMock()
    response = MagicMock(status_code=400)
    response.json.return_value = {"msg": "错误"}
    session.post.return_value = response
    captcha = CaptchaResult(sec="sec123", image_bytes=b"png")

    with pytest.raises(RuntimeError, match="HTTP 400"):
        submit_captcha(session, captcha, "地球")


def test_cookies_for_httpx() -> None:
    session = CNVDSession(
        _cookies=[
            {
                "name": "__jsluid_s",
                "value": "uid",
                "domain": "www.cnvd.org.cn",
                "path": "/",
            }
        ]
    )
    assert session.is_authenticated
    assert session.cookies_for_httpx() == session._cookies


def _mock_request_cookie(name: str, value: str) -> MagicMock:
    cookie = MagicMock()
    cookie.name = name
    cookie.value = value
    cookie.domain = "www.cnvd.org.cn"
    cookie.path = "/"
    cookie.expires = None
    cookie.secure = True
    return cookie


def test_ensure_authenticated_refresh_deletes_stale_file(tmp_path: Path) -> None:
    cookie_path = tmp_path / "cnvd_session_cookies.json"
    cookie_path.write_text('{"__jsluid_s": {"value": "stale", "domain": "www.cnvd.org.cn"}}', encoding="utf-8")
    session = CNVDSession(cookie_path=cookie_path, max_retries=1)

    requests_session = MagicMock()
    requests_session.cookies = [_mock_request_cookie("__jsluid_s", "fresh")]
    requests_session.get.side_effect = [MagicMock(status_code=200), MagicMock(status_code=200)]

    requests_mod = MagicMock()
    session_cm = MagicMock()
    session_cm.__enter__.return_value = requests_session
    session_cm.__exit__.return_value = False
    requests_mod.Session.return_value = session_cm

    with (
        patch("vuln_scraper.scrapers.cnvd.session._import_cnvd_deps") as import_deps,
        patch("vuln_scraper.scrapers.cnvd.session.visit"),
        patch("vuln_scraper.scrapers.cnvd.session.get_captcha", return_value=CaptchaResult(sec="s", image_bytes=b"i")),
        patch("vuln_scraper.scrapers.cnvd.session.submit_captcha"),
        patch("vuln_scraper.scrapers.cnvd.session.ocr_classify", return_value="地球"),
    ):
        import_deps.return_value = (
            MagicMock(DdddOcr=MagicMock()),
            MagicMock(Context=MagicMock()),
            requests_mod,
        )
        session.ensure_authenticated(refresh_cookies=True, persist_cookies=False)

    assert not cookie_path.exists()
    assert session.is_authenticated
    assert session.cookies_for_httpx()[0]["value"] == "fresh"


def test_ensure_authenticated_persists_cookies(tmp_path: Path) -> None:
    cookie_path = tmp_path / "cnvd_session_cookies.json"
    session = CNVDSession(cookie_path=cookie_path, max_retries=1)

    requests_session = MagicMock()
    requests_session.cookies = [_mock_request_cookie("__jsluid_s", "saved")]
    visit_response = MagicMock(status_code=200)
    verify_response = MagicMock(status_code=200)
    requests_session.get.side_effect = [visit_response, verify_response]

    captcha = CaptchaResult(sec="sec", image_bytes=b"img")
    ocr = MagicMock()
    ocr.classification.return_value = "地球"
    ctx = MagicMock()

    requests_mod = MagicMock()
    session_cm = MagicMock()
    session_cm.__enter__.return_value = requests_session
    session_cm.__exit__.return_value = False
    requests_mod.Session.return_value = session_cm

    with (
        patch("vuln_scraper.scrapers.cnvd.session._import_cnvd_deps") as import_deps,
        patch("vuln_scraper.scrapers.cnvd.session.visit"),
        patch("vuln_scraper.scrapers.cnvd.session.get_captcha", return_value=captcha),
        patch("vuln_scraper.scrapers.cnvd.session.submit_captcha"),
    ):
        import_deps.return_value = (
            MagicMock(DdddOcr=MagicMock(return_value=ocr)),
            MagicMock(Context=MagicMock(return_value=ctx)),
            requests_mod,
        )
        session.ensure_authenticated(refresh_cookies=False, persist_cookies=True)

    assert cookie_path.exists()
    assert session.is_authenticated


def test_ensure_authenticated_raises_after_max_retries(tmp_path: Path) -> None:
    cookie_path = tmp_path / "cnvd_session_cookies.json"
    session = CNVDSession(cookie_path=cookie_path, max_retries=1)

    requests_session = MagicMock()
    requests_session.cookies = []
    ocr = MagicMock()
    ocr.classification.return_value = "xx"
    ctx = MagicMock()

    requests_mod = MagicMock()
    session_cm = MagicMock()
    session_cm.__enter__.return_value = requests_session
    session_cm.__exit__.return_value = False
    requests_mod.Session.return_value = session_cm

    with (
        patch("vuln_scraper.scrapers.cnvd.session._import_cnvd_deps") as import_deps,
        patch("vuln_scraper.scrapers.cnvd.session.visit"),
        patch("vuln_scraper.scrapers.cnvd.session.get_captcha", return_value=CaptchaResult(sec="s", image_bytes=b"i")),
        patch("vuln_scraper.scrapers.cnvd.session.time.sleep"),
    ):
        import_deps.return_value = (
            MagicMock(DdddOcr=MagicMock(return_value=ocr)),
            MagicMock(Context=MagicMock(return_value=ctx)),
            requests_mod,
        )
        with pytest.raises(CNVDSessionError, match="failed after"):
            session.ensure_authenticated()


def test_import_cnvd_deps_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    def raise_missing() -> None:
        raise CNVDSessionError("pip install -e '.[cnvd]'")

    monkeypatch.setattr("vuln_scraper.scrapers.cnvd.session._import_cnvd_deps", raise_missing)
    session = CNVDSession(cookie_path=Path("x.json"))
    with pytest.raises(CNVDSessionError, match="cnvd"):
        session.ensure_authenticated()
