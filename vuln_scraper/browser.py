from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .captcha_solver import (
    CaptchaMap,
    hash_captcha_data_url,
    hash_captcha_image_bytes,
    resolve_captcha_map_path,
)
from .config import DEFAULT_USER_AGENT


@dataclass(slots=True)
class BrowserFetchResult:
    html: str
    url: str
    status_code: int | None
    cookies: list[dict[str, Any]]


class BrowserVerificationTimeout(RuntimeError):
    """Raised when a manual verification page never reaches scraper content."""


_CNVD_CAPTCHA_UPDATE_SELECTOR = "#update"

_CAPTCHA_HELPERS_JS = r"""
const visible = (el) => {
    if (!el) return false;
    const style = window.getComputedStyle(el);
    const rect = el.getBoundingClientRect();
    return style.display !== "none" &&
        style.visibility !== "hidden" &&
        rect.width > 0 &&
        rect.height > 0;
};
const textOf = (el) => el ? (el.innerText || el.textContent || "") : "";
const srcFor = (img) => {
    if (!img) return "";
    const raw = (img.getAttribute("src") || "").trim();
    const resolved = img.currentSrc || img.src || "";
    if (raw) {
        return resolved || raw;
    }
    return resolved && resolved !== window.location.href ? resolved : "";
};
const captchaHint = /captcha|verify|verification|validate|valid|check.?code|image.?code|rand|code|yzm|验证码/i;
const refreshText = /换一张|看不清|刷新|update/i;
const inputSelector = 'input[type="text"], input:not([type]), input[type="search"]';
const scopeSelector = "form, table, tbody, tr, td, div, p, span, body";

const nearestScope = (el) => {
    if (!el) return document.body || document.documentElement;
    return el.closest(scopeSelector) || document.body || document.documentElement;
};

const firstVisibleInput = (scope) => {
    const root = scope || document;
    return [...root.querySelectorAll(inputSelector)].find(visible) || null;
};

const imageMeta = (img) => [
    srcFor(img),
    img.getAttribute("src") || "",
    img.id || "",
    String(img.className || ""),
    img.getAttribute("alt") || "",
    img.getAttribute("title") || "",
    img.getAttribute("name") || "",
].join(" ");

const scoreImage = (img, update) => {
    const src = srcFor(img);
    const scope = nearestScope(img);
    let score = 0;
    if (/^data:image/i.test(src)) score += 4;
    if (captchaHint.test(imageMeta(img))) score += 3;
    if (update && nearestScope(update).contains(img)) score += 5;
    if (/验证码/.test(textOf(scope))) score += 2;
    const rect = img.getBoundingClientRect();
    if (rect.width >= 40 && rect.height >= 15 && rect.width <= 320 && rect.height <= 140) score += 1;
    return score;
};

const nearestVisibleImageTo = (element) => {
    if (!element) return null;
    const images = [...document.querySelectorAll("img[src]")].filter(visible);
    const origin = element.getBoundingClientRect();
    let best = null;
    for (const img of images) {
        const rect = img.getBoundingClientRect();
        const dx = Math.abs((rect.left + rect.width / 2) - (origin.left + origin.width / 2));
        const dy = Math.abs((rect.top + rect.height / 2) - (origin.top + origin.height / 2));
        const distance = dx + dy;
        if (!best || distance < best.distance) {
            best = { img, distance };
        }
    }
    return best && best.distance < 500 ? best.img : null;
};

function findCnvdCaptcha() {
    const update = document.querySelector("#update");
    const bodyText = textOf(document.body);

    if (update) {
        const updateScope = nearestScope(update);
        const scopedImages = [...updateScope.querySelectorAll("img[src]")].filter(visible);
        let img = scopedImages
            .map((candidate) => ({ img: candidate, score: scoreImage(candidate, update) }))
            .sort((a, b) => b.score - a.score)[0]?.img || null;
        if (!img) {
            img = nearestVisibleImageTo(update);
        }
        if (img) {
            const scope = nearestScope(img);
            const input = firstVisibleInput(scope) || firstVisibleInput(updateScope) || firstVisibleInput(document);
            return { img, scope, input, update };
        }
    }

    const likely = [...document.querySelectorAll("img[src]")]
        .filter(visible)
        .map((img) => ({ img, score: scoreImage(img, update) }))
        .filter((candidate) => candidate.score >= 3 || (candidate.score >= 1 && /验证码/.test(bodyText)))
        .sort((a, b) => b.score - a.score)[0];
    if (!likely) {
        return null;
    }

    const scope = nearestScope(likely.img);
    const input = firstVisibleInput(scope) || (/验证码/.test(bodyText) ? firstVisibleInput(document) : null);
    if (!input && !update && !/验证码/.test(bodyText)) {
        return null;
    }
    return { img: likely.img, scope, input, update };
}
"""

_CAPTCHA_DETECT_JS = (
    "() => {\n"
    + _CAPTCHA_HELPERS_JS
    + r"""
    const found = findCnvdCaptcha();
    if (!found) {
        return null;
    }
    return {
        src: srcFor(found.img),
        hasInput: Boolean(found.input),
        hasRefresh: Boolean(found.update),
        hasSubmit: true,
    };
}"""
)

_CAPTCHA_PRESENT_JS = (
    "() => {\n"
    + _CAPTCHA_HELPERS_JS
    + "\n    return Boolean(findCnvdCaptcha());\n}"
)

_CAPTCHA_SUBMIT_JS = (
    "(answer) => {\n"
    + _CAPTCHA_HELPERS_JS
    + r"""
    const found = findCnvdCaptcha();
    if (!found) {
        return { ok: false, reason: "no-captcha" };
    }
    const input = found.input;
    if (!input) {
        return { ok: false, reason: "no-input" };
    }
    input.focus();
    input.value = answer;
    input.dispatchEvent(new Event("input", { bubbles: true }));
    input.dispatchEvent(new Event("change", { bubbles: true }));
    const controlSelector = "button,input[type='submit'],input[type='button'],a";
    const controls = [
        ...new Set([
            ...found.scope.querySelectorAll(controlSelector),
            ...document.querySelectorAll(controlSelector),
        ]),
    ].filter(visible);
    const submit = controls.find((el) => {
        if (el.id === "update") return false;
        const text = (el.innerText || el.value || "").trim();
        return (el.id === "submit" || /提交|确定|验证|登录|确认/.test(text)) && !refreshText.test(text);
    });
    if (submit) {
        submit.click();
        return { ok: true, reason: "clicked-submit" };
    }
    const form = input.form || input.closest("form");
    if (form && typeof form.requestSubmit === "function") {
        form.requestSubmit();
        return { ok: true, reason: "form-submit" };
    }
    input.dispatchEvent(new KeyboardEvent("keydown", { key: "Enter", bubbles: true }));
    input.dispatchEvent(new KeyboardEvent("keyup", { key: "Enter", bubbles: true }));
    return { ok: true, reason: "enter-key" };
}"""
)

_PAGE_BLOCKED_JS = (
    "() => {\n"
    + _CAPTCHA_HELPERS_JS
    + r"""
    const body = document.body ? document.body.innerText : "";
    if (!body.trim()) {
        return true;
    }
    const html = document.documentElement
        ? document.documentElement.innerHTML.toLowerCase()
        : "";
    const jsl = html.includes("jiasule") || html.includes("__jsl_clearance");
    if (findCnvdCaptcha()) {
        return true;
    }
    return jsl && !document.querySelector("table");
}"""
)


async def _wait_until(condition, *, timeout_seconds: float, interval_seconds: float = 0.25) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout_seconds
    while asyncio.get_running_loop().time() < deadline:
        if await condition():
            return True
        await asyncio.sleep(interval_seconds)
    return await condition()

class BrowserHTMLFetcher:
    def __init__(
        self,
        *,
        headless: bool = True,
        timeout_ms: int = 30_000,
        chrome_executable: str | None = None,
        user_data_dir: str | Path | None = None,
        manual_verification: bool = False,
        captcha_map_path: str | Path | None = None,
        data_dir: str | Path | None = None,
        browser_gate_url: str | None = None,
        captcha_update_selector: str = _CNVD_CAPTCHA_UPDATE_SELECTOR,
        proxy_url: str | None = None,
    ) -> None:
        self.headless = headless
        self.timeout_ms = timeout_ms
        self.chrome_executable = chrome_executable
        self.proxy_url = proxy_url.strip() if proxy_url and proxy_url.strip() else None
        self.user_data_dir = Path(user_data_dir) if user_data_dir is not None else None
        self.manual_verification = manual_verification
        self.browser_gate_url = browser_gate_url
        self.captcha_update_selector = captcha_update_selector
        self._site_gate_cleared = False
        unknown_dir = Path(data_dir) if data_dir is not None else Path("data")
        self.unknown_captcha_path = unknown_dir / "cnvd_unknown_captchas.json"
        self._unknown_captcha_hashes: set[str] = set()
        self.captcha_map: CaptchaMap | None = None
        resolved_map = resolve_captcha_map_path(
            explicit=Path(captcha_map_path) if captcha_map_path is not None else None,
            data_dir=Path(data_dir) if data_dir is not None else None,
        )
        if resolved_map is not None:
            self.captcha_map = CaptchaMap.load(resolved_map)
        self._playwright = None
        self._browser = None
        self._context = None
        self._persistent_context = False

    async def __aenter__(self) -> "BrowserHTMLFetcher":
        try:
            from playwright.async_api import async_playwright
        except ImportError as exc:
            raise RuntimeError(
                "Playwright is not installed. Install with `pip install -e .[browser]` "
                "or run without --browser-fallback."
            ) from exc

        self._playwright = await async_playwright().start()
        launch_kwargs: dict[str, Any] = {
            "headless": self.headless,
            "args": ["--disable-blink-features=AutomationControlled"],
        }
        if self.chrome_executable:
            launch_kwargs["executable_path"] = self.chrome_executable

        context_kwargs: dict[str, Any] = {
            "user_agent": DEFAULT_USER_AGENT,
            "locale": "zh-CN",
            "viewport": {"width": 1440, "height": 1100},
            "extra_http_headers": {"Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8"},
        }
        if self.proxy_url:
            context_kwargs["proxy"] = {"server": self.proxy_url}
            context_kwargs["ignore_https_errors"] = True
        if self.user_data_dir is not None:
            self.user_data_dir.mkdir(parents=True, exist_ok=True)
            self._context = await self._playwright.chromium.launch_persistent_context(
                str(self.user_data_dir),
                **launch_kwargs,
                **context_kwargs,
            )
            self._browser = self._context.browser
            self._persistent_context = True
        else:
            self._browser = await self._playwright.chromium.launch(**launch_kwargs)
            self._context = await self._browser.new_context(**context_kwargs)

        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._context is not None:
            await self._context.close()
        if self._browser is not None and not self._persistent_context:
            await self._browser.close()
        if self._playwright is not None:
            await self._playwright.stop()

    def _uses_cnvd_gate(self, url: str) -> bool:
        return (
            self.captcha_map is not None
            and self.browser_gate_url is not None
            and "cnvd.org.cn" in url
        )

    @staticmethod
    def _is_cnvd_page(page) -> bool:
        return "cnvd.org.cn" in str(getattr(page, "url", ""))

    async def _cnvd_captcha_present(self, page) -> bool:
        if not self._is_cnvd_page(page):
            return False
        try:
            return bool(await page.evaluate(_CAPTCHA_PRESENT_JS))
        except Exception:
            return False

    async def _clear_site_gate(self, page) -> None:
        if self.browser_gate_url is None or self._site_gate_cleared:
            return

        await page.goto(self.browser_gate_url, wait_until="domcontentloaded", timeout=self.timeout_ms)
        if await self._solve_cnvd_captcha(page):
            self._site_gate_cleared = True

    async def _solve_cnvd_captcha(self, page) -> bool:
        if self.captcha_map is None:
            return not await self._cnvd_captcha_present(page)

        deadline = asyncio.get_running_loop().time() + (self.timeout_ms / 1000)
        rotations = 0

        while asyncio.get_running_loop().time() < deadline:
            if not await self._cnvd_captcha_present(page) and not await self._page_is_blocked(page):
                return True

            image_hash = await self._captcha_image_hash(page)
            if not image_hash:
                await asyncio.sleep(0.5)
                continue

            answer = self.captcha_map.lookup(image_hash)
            if answer is None:
                await self._record_unknown_captcha(page, image_hash)
                if not await self._refresh_cnvd_captcha(page):
                    await asyncio.sleep(0.5)
                rotations += 1
                continue

            submit_result = await self._submit_captcha_answer(page, answer)
            cleared = await _wait_until(
                lambda: self._content_ready(page),
                timeout_seconds=15,
            )
            if cleared or not await self._cnvd_captcha_present(page):
                return True
            await self._refresh_cnvd_captcha(page)
            rotations += 1

        return not await self._cnvd_captcha_present(page)

    async def _record_unknown_captcha(self, page, image_hash: str) -> None:
        if image_hash in self._unknown_captcha_hashes:
            return
        src = await self._captcha_image_src(page)
        if not src or not src.startswith("data:image"):
            return

        self._unknown_captcha_hashes.add(image_hash)
        now = datetime.now(UTC).isoformat()
        try:
            raw = json.loads(self.unknown_captcha_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            raw = {}
        if not isinstance(raw, dict):
            raw = {}

        existing = raw.get(image_hash)
        entry = existing if isinstance(existing, dict) else {}
        entry.setdefault("answer", "")
        entry.setdefault("first_seen_at", now)
        entry["last_seen_at"] = now
        entry["seen_count"] = int(entry.get("seen_count") or 0) + 1
        entry["src_url"] = src
        raw[image_hash] = entry

        try:
            self.unknown_captcha_path.parent.mkdir(parents=True, exist_ok=True)
            self.unknown_captcha_path.write_text(
                json.dumps(raw, ensure_ascii=False, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except OSError:
            pass

    async def _page_is_blocked(self, page) -> bool:
        try:
            return bool(await page.evaluate(_PAGE_BLOCKED_JS))
        except Exception:
            return True

    async def fetch(self, url: str) -> BrowserFetchResult:
        if self._context is None:
            raise RuntimeError("BrowserHTMLFetcher must be used as an async context manager.")

        page = await self._context.new_page()
        response = None
        try:
            if self._uses_cnvd_gate(url):
                await self._clear_site_gate(page)
            response = await page.goto(url, wait_until="domcontentloaded", timeout=self.timeout_ms)
            ready = await self._wait_for_real_content(page)
            if not ready and (self.manual_verification or self.captcha_map is not None):
                timeout_seconds = max(1, self.timeout_ms // 1000)
                raise BrowserVerificationTimeout(
                    "verification was not completed before "
                    f"the {timeout_seconds}s browser timeout"
                )
            html = await page.content()
            cookies = await self._context.cookies(url)
            return BrowserFetchResult(
                html=html,
                url=page.url,
                status_code=response.status if response else None,
                cookies=cookies,
            )
        finally:
            await page.close()

    async def _content_ready(self, page) -> bool:
        if await self._detect_captcha(page) is not None:
            return False
        try:
            return await page.evaluate(
                """() => {
                    const body = document.body ? document.body.innerText : "";
                    return Boolean(
                        document.querySelector("table") ||
                        document.querySelector("span.header__title__text") ||
                        document.querySelector(".CoveoResult") ||
                        document.querySelector("c-quantic-result") ||
                        document.querySelector(".quantic-result") ||
                        document.querySelector(".security-advisory") ||
                        document.querySelector(".news-list") ||
                        document.querySelector(".article-list") ||
                        document.querySelector(".blkContainerSblk") ||
                        document.querySelector(".gg_detail") ||
                        body.includes("AVD-") ||
                        body.includes("CNVD-") ||
                        body.includes("JSA") ||
                        body.includes("Security Advisories") ||
                        body.includes("Security Advisory") ||
                        body.includes("Hikvision") ||
                        body.includes("漏洞标题") ||
                        body.includes("危害级别") ||
                        body.includes("漏洞名称")
                    );
                }"""
            )
        except Exception:
            return False

    async def _detect_captcha(self, page) -> dict[str, Any] | None:
        if not self._is_cnvd_page(page):
            return None
        try:
            state = await page.evaluate(_CAPTCHA_DETECT_JS)
        except Exception:
            return None
        return state if isinstance(state, dict) else None

    async def _captcha_image_src(self, page) -> str | None:
        state = await self._detect_captcha(page)
        src = state.get("src") if state else None
        return str(src) if src else None

    async def _captcha_image_hash(self, page) -> str | None:
        src = await self._captcha_image_src(page)
        if not src:
            return None
        if src.startswith("data:image"):
            image_hash = hash_captcha_data_url(src)
            if image_hash:
                return image_hash
        if src.startswith("http"):
            try:
                response = await page.request.get(src, timeout=10_000)
                if response.ok:
                    return hash_captcha_image_bytes(await response.body())
            except Exception:
                pass
        return None

    async def _wait_for_captcha_hash_change(self, page, previous_hash: str | None) -> str | None:
        deadline = asyncio.get_running_loop().time() + 5.0
        while asyncio.get_running_loop().time() < deadline:
            current_hash = await self._captcha_image_hash(page)
            if current_hash and current_hash != previous_hash:
                return current_hash
            await asyncio.sleep(0.15)
        return await self._captcha_image_hash(page)

    async def _refresh_cnvd_captcha(self, page) -> bool:
        previous_hash = await self._captcha_image_hash(page)
        update_link = page.locator(self.captcha_update_selector).first
        if await update_link.count() == 0:
            return False

        try:
            await update_link.click(timeout=3_000)
        except Exception:
            return False

        new_hash = await self._wait_for_captcha_hash_change(page, previous_hash)
        changed = bool(new_hash and new_hash != previous_hash)
        return changed

    async def _refresh_captcha(self, page) -> bool:
        return await self._refresh_cnvd_captcha(page)

    async def _submit_captcha_answer(self, page, answer: str) -> dict[str, Any]:
        try:
            result = await page.evaluate(_CAPTCHA_SUBMIT_JS, answer)
        except Exception as exc:
            return {"ok": False, "reason": "submit-js-failed", "error": str(exc)}
        return result if isinstance(result, dict) else {"ok": False, "reason": "bad-submit-result"}

    async def _attempt_captcha_solve(self, page) -> bool:
        if self.captcha_map is None:
            return False

        state = await self._detect_captcha(page)
        if state is None:
            return False

        image_hash = await self._captcha_image_hash(page)
        if not image_hash:
            await self._refresh_cnvd_captcha(page)
            return False

        answer = self.captcha_map.lookup(image_hash)
        if answer is None:
            await self._refresh_cnvd_captcha(page)
            return False

        if not state.get("hasInput"):
            await self._refresh_cnvd_captcha(page)
            return False

        try:
            submit_result = await self._submit_captcha_answer(page, answer)
        except Exception:
            await self._refresh_cnvd_captcha(page)
            return False
        if not submit_result.get("ok"):
            await self._refresh_cnvd_captcha(page)
            return False

        await asyncio.sleep(0.8)
        if await self._content_ready(page):
            return True
        if await self._detect_captcha(page) is not None:
            await self._refresh_cnvd_captcha(page)
        return False

    def _max_captcha_attempts(self) -> int:
        if self.captcha_map is None:
            return 0
        return max(len(self.captcha_map), 36)

    async def _wait_for_real_content(self, page) -> bool:
        deadline = asyncio.get_running_loop().time() + (self.timeout_ms / 1000)
        last_html = ""
        captcha_attempts = 0
        seen_hashes: set[str] = set()
        max_captcha_attempts = self._max_captcha_attempts()

        while asyncio.get_running_loop().time() < deadline:
            if await self._content_ready(page):
                try:
                    await page.wait_for_load_state("networkidle", timeout=5_000)
                except Exception:
                    pass
                return True

            if await self._cnvd_captcha_present(page):
                if captcha_attempts >= max_captcha_attempts:
                    break
                captcha_attempts += 1
                if not await self._solve_cnvd_captcha(page):
                    await asyncio.sleep(0.5)

            current_html = await page.content()
            if current_html != last_html:
                last_html = current_html
            await asyncio.sleep(0.5)

        await page.wait_for_load_state("domcontentloaded", timeout=5_000)
        return False
