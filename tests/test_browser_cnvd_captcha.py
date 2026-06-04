import asyncio
import json
import threading

import pytest
from playwright.sync_api import sync_playwright

from vuln_scraper.browser import BrowserHTMLFetcher, _CAPTCHA_DETECT_JS, _CAPTCHA_PRESENT_JS, _CAPTCHA_SUBMIT_JS
from vuln_scraper.captcha_solver import hash_captcha_data_url


@pytest.fixture(scope="module")
def browser_page():
    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch(headless=True)
        except Exception as exc:
            pytest.skip(f"Playwright browser is not available: {exc}")
        page = browser.new_page()
        yield page
        browser.close()


def test_cnvd_captcha_detector_finds_url_image_near_update(browser_page) -> None:
    browser_page.set_content(
        """
        <input id="site-search" type="text">
        <img id="logo" src="https://www.cnvd.org.cn/logo.png" style="width: 180px; height: 48px">
        <form id="verify">
          <label>验证码</label>
          <img id="captcha-img" src="https://www.cnvd.org.cn/verifyCode?tick=1" style="width: 120px; height: 50px">
          <input id="captcha-text" type="text">
          <a id="update" href="#">换一张</a>
          <button type="button" onclick="window.submittedCaptcha = document.querySelector('#captcha-text').value">提交</button>
        </form>
        """
    )

    state = browser_page.evaluate(_CAPTCHA_DETECT_JS)

    assert browser_page.evaluate(_CAPTCHA_PRESENT_JS)
    assert state["src"] == "https://www.cnvd.org.cn/verifyCode?tick=1"
    assert state["hasInput"]
    assert state["hasRefresh"]


def test_cnvd_captcha_submit_uses_captcha_input_not_search(browser_page) -> None:
    browser_page.set_content(
        """
        <input id="site-search" type="text">
        <form id="verify">
          <span>验证码</span>
          <img src="https://www.cnvd.org.cn/verifyCode?tick=2" style="width: 120px; height: 50px">
          <input id="captcha-text" type="text">
          <a id="update" href="#">换一张</a>
          <button type="button" onclick="window.submittedCaptcha = document.querySelector('#captcha-text').value">提交</button>
        </form>
        """
    )

    result = browser_page.evaluate(_CAPTCHA_SUBMIT_JS, "answer42")

    assert result["ok"]
    assert browser_page.locator("#site-search").input_value() == ""
    assert browser_page.locator("#captcha-text").input_value() == "answer42"
    assert browser_page.evaluate("window.submittedCaptcha") == "answer42"


def test_cnvd_captcha_submit_finds_button_outside_image_scope(browser_page) -> None:
    browser_page.set_content(
        """
        <div class="mb20">
          <span>验证码</span>
          <img src="https://www.cnvd.org.cn/verifyCode?tick=3" style="width: 120px; height: 50px">
          <input id="captcha-text" type="text">
          <span>看不清？<a id="update" href="#">换一张</a></span>
        </div>
        <button id="submit" type="submit" onclick="window.submittedCaptcha = document.querySelector('#captcha-text').value">提交验证码</button>
        """
    )

    result = browser_page.evaluate(_CAPTCHA_SUBMIT_JS, "answer99")

    assert result["ok"]
    assert result["reason"] == "clicked-submit"
    assert browser_page.evaluate("window.submittedCaptcha") == "answer99"


def test_cnvd_captcha_detector_waits_on_empty_cap_image_src(browser_page) -> None:
    browser_page.set_content(
        """
        <form>
          <span>验证码</span>
          <img id="cap-img" alt="验证码" src="" style="width: 120px; height: 50px">
          <input id="captcha-text" type="text">
          <a id="update" href="#">换一张</a>
        </form>
        """
    )

    state = browser_page.evaluate(_CAPTCHA_DETECT_JS)

    assert browser_page.evaluate(_CAPTCHA_PRESENT_JS)
    assert state["src"] == ""


def test_cnvd_captcha_detector_ignores_regular_content_images(browser_page) -> None:
    browser_page.set_content(
        """
        <img src="https://www.cnvd.org.cn/logo.png" style="width: 180px; height: 48px">
        <input type="search">
        <table><tr><td>CNVD-2026-21550</td></tr></table>
        """
    )

    assert browser_page.evaluate(_CAPTCHA_DETECT_JS) is None
    assert not browser_page.evaluate(_CAPTCHA_PRESENT_JS)


def test_cnvd_unknown_captcha_is_written_for_labeling(tmp_path) -> None:
    src_url = "data:image/png;base64,Y252ZC11bmtub3du"
    image_hash = hash_captcha_data_url(src_url)
    fetcher = BrowserHTMLFetcher(data_dir=tmp_path)

    class Page:
        url = "https://www.cnvd.org.cn/"

        async def evaluate(self, script):
            return {"src": src_url}

    assert image_hash is not None
    _run_async(fetcher._record_unknown_captcha(Page(), image_hash))

    raw = json.loads((tmp_path / "cnvd_unknown_captchas.json").read_text(encoding="utf-8"))
    assert raw[image_hash]["answer"] == ""
    assert raw[image_hash]["src_url"] == src_url
    assert raw[image_hash]["seen_count"] == 1


def test_fetcher_skips_cnvd_captcha_detection_on_avd_pages(tmp_path) -> None:
    fetcher = BrowserHTMLFetcher(data_dir=tmp_path)

    class Page:
        url = "https://avd.aliyun.com/high-risk/list?page=1"

        async def evaluate(self, script):
            raise AssertionError("CNVD captcha detector should not run for AVD")

    assert _run_async_value(fetcher._detect_captcha(Page())) is None
    assert _run_async_value(fetcher._cnvd_captcha_present(Page())) is False


def _run_async(coro) -> None:
    error: list[BaseException] = []

    def target() -> None:
        try:
            asyncio.run(coro)
        except BaseException as exc:
            error.append(exc)

    thread = threading.Thread(target=target)
    thread.start()
    thread.join()
    if error:
        raise error[0]


def _run_async_value(coro):
    result = []
    error: list[BaseException] = []

    def target() -> None:
        try:
            result.append(asyncio.run(coro))
        except BaseException as exc:
            error.append(exc)

    thread = threading.Thread(target=target)
    thread.start()
    thread.join()
    if error:
        raise error[0]
    return result[0]
