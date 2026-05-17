"""
WonderwallAi Headless Probe Service.

A separate Railway service from the main wonderwallai API. Runs Playwright +
Chromium to probe chat widgets that don't expose a clean /api/chat endpoint
(Intercom, Crisp, Drift, Tidio, Tawk.to, plus a generic fallback).

Single endpoint: POST /probe-widget. Auth via shared HEADLESS_INTERNAL_TOKEN
since this service is only ever called from the main wonderwallai server.
"""

import asyncio
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, Header, HTTPException
from playwright.async_api import async_playwright, Browser, Page, Frame
from pydantic import BaseModel, Field

from widget_detector import KNOWN_WIDGETS, WidgetTarget, generic_input_selectors

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("wonderwallai.headless")

INTERNAL_TOKEN = os.getenv("HEADLESS_INTERNAL_TOKEN", "")
if not INTERNAL_TOKEN:
    logger.warning("HEADLESS_INTERNAL_TOKEN not set; service will reject all calls.")

PAGE_TIMEOUT_MS = 25_000
WIDGET_TIMEOUT_MS = 8_000
RESPONSE_WAIT_MS = 12_000

_browser: Optional[Browser] = None
_pw_ctx = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _browser, _pw_ctx
    _pw_ctx = await async_playwright().start()
    _browser = await _pw_ctx.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
    )
    logger.info("Chromium ready.")
    yield
    if _browser:
        await _browser.close()
    if _pw_ctx:
        await _pw_ctx.stop()
    logger.info("Chromium shut down.")


app = FastAPI(title="WonderwallAi Headless Probe", version="1.0.0", lifespan=lifespan)


# ============================================================
# Request / response models
# ============================================================

class AttackPayload(BaseModel):
    id: str
    title: str
    payload: str


class ProbeRequest(BaseModel):
    url: str = Field(..., min_length=8, max_length=2048)
    attacks: list[AttackPayload] = Field(..., max_length=30)


class AttackOutcome(BaseModel):
    id: str
    title: str
    response_excerpt: str = ""
    error: Optional[str] = None
    duration_ms: float = 0.0


class ProbeResponse(BaseModel):
    url: str
    widget_vendor: Optional[str] = None
    chat_found: bool
    outcomes: list[AttackOutcome] = []
    note: str = ""


# ============================================================
# Endpoints
# ============================================================

@app.get("/health")
async def health():
    return {"ok": True, "browser_ready": _browser is not None}


@app.post("/probe-widget", response_model=ProbeResponse)
async def probe_widget(
    req: ProbeRequest,
    x_internal_token: str = Header(default=""),
):
    """
    Open the URL in headless Chromium, find the chat widget, and run each
    attack payload through it. Returns per-attack response excerpts that
    the caller (the main wonderwallai server) evaluates with its
    success-detector logic.
    """
    if not INTERNAL_TOKEN or x_internal_token != INTERNAL_TOKEN:
        raise HTTPException(status_code=401, detail="Invalid internal token.")
    if _browser is None:
        raise HTTPException(status_code=503, detail="Browser not ready.")

    return await _probe(req)


# ============================================================
# Core probe flow
# ============================================================

async def _probe(req: ProbeRequest) -> ProbeResponse:
    context = await _browser.new_context(
        user_agent="WonderwallAi-Scanner/1.0 (+https://wonderwallai.skintlabs.ai)",
        viewport={"width": 1280, "height": 900},
        ignore_https_errors=True,
    )
    page = await context.new_page()
    page.set_default_timeout(PAGE_TIMEOUT_MS)

    try:
        try:
            await page.goto(req.url, wait_until="domcontentloaded", timeout=PAGE_TIMEOUT_MS)
        except Exception as e:
            return ProbeResponse(
                url=req.url, chat_found=False,
                note=f"Page failed to load: {type(e).__name__}",
            )

        target = await _detect_widget(page)
        if target is None:
            return ProbeResponse(
                url=req.url, chat_found=False,
                note="No recognised chat widget found on the page.",
            )

        outcomes: list[AttackOutcome] = []
        for atk in req.attacks:
            outcome = await _run_one_attack(page, target, atk)
            outcomes.append(outcome)
            # Small delay to let widget settle between attacks
            await asyncio.sleep(0.4)

        return ProbeResponse(
            url=req.url,
            widget_vendor=target.vendor,
            chat_found=True,
            outcomes=outcomes,
        )
    finally:
        await context.close()


# ============================================================
# Widget detection + interaction
# ============================================================

async def _detect_widget(page: Page) -> Optional[WidgetTarget]:
    """Try each known vendor; fall back to a generic input scan."""
    for fingerprint, target in KNOWN_WIDGETS:
        try:
            el = await page.query_selector(fingerprint)
            if el is not None:
                logger.info(f"Detected widget: {target.vendor}")
                return target
        except Exception:
            continue

    # Generic fallback: any chat-shaped input visible on the page
    for sel in generic_input_selectors():
        try:
            el = await page.query_selector(sel)
            if el is not None:
                visible = await el.is_visible()
                if visible:
                    logger.info(f"Detected generic chat input via selector: {sel}")
                    return WidgetTarget(
                        vendor="generic",
                        open_selector=None,
                        iframe_selector=None,
                        input_selector=sel,
                        send_strategy="enter_key",
                        send_selector=None,
                        response_selector="[role='log'] *, [class*='message'], [class*='response'], [data-message-author-role]",
                    )
        except Exception:
            continue
    return None


async def _frame_for(page: Page, target: WidgetTarget) -> Page | Frame:
    """Resolve the page-or-frame where the input lives."""
    if target.iframe_selector:
        try:
            handle = await page.wait_for_selector(target.iframe_selector, timeout=WIDGET_TIMEOUT_MS)
            frame = await handle.content_frame()
            if frame is not None:
                return frame
        except Exception:
            pass
    return page


async def _open_widget(page: Page, target: WidgetTarget) -> None:
    """If the widget is collapsed, click its launcher."""
    if not target.open_selector:
        return
    try:
        launcher = await page.query_selector(target.open_selector)
        if launcher and await launcher.is_visible():
            await launcher.click(timeout=WIDGET_TIMEOUT_MS)
            await asyncio.sleep(0.6)
    except Exception:
        pass  # Some launchers are inside iframes; the input wait will still work


async def _run_one_attack(page: Page, target: WidgetTarget, atk) -> AttackOutcome:
    import time
    start = time.perf_counter()

    try:
        await _open_widget(page, target)
        ctx = await _frame_for(page, target)

        try:
            await ctx.wait_for_selector(target.input_selector, timeout=WIDGET_TIMEOUT_MS)
        except Exception:
            return AttackOutcome(
                id=atk.id, title=atk.title,
                error="input_not_found",
                duration_ms=(time.perf_counter() - start) * 1000,
            )

        # Snapshot existing response text so we can diff after sending
        before = await _read_responses(ctx, target)

        # Type the attack
        try:
            await ctx.fill(target.input_selector, atk.payload)
        except Exception:
            # Some composers are contenteditable rather than textarea
            try:
                await ctx.click(target.input_selector)
                await ctx.keyboard.type(atk.payload)
            except Exception as e:
                return AttackOutcome(
                    id=atk.id, title=atk.title,
                    error=f"fill_failed:{type(e).__name__}",
                    duration_ms=(time.perf_counter() - start) * 1000,
                )

        # Send
        if target.send_strategy == "click_send" and target.send_selector:
            try:
                await ctx.click(target.send_selector, timeout=WIDGET_TIMEOUT_MS)
            except Exception:
                await ctx.keyboard.press("Enter")
        else:
            await ctx.keyboard.press("Enter")

        # Wait for a new response
        new_text = await _wait_for_new_response(ctx, target, before)
        return AttackOutcome(
            id=atk.id, title=atk.title,
            response_excerpt=new_text[:600],
            duration_ms=(time.perf_counter() - start) * 1000,
        )

    except Exception as e:
        logger.warning(f"Attack {atk.id} failed unexpectedly: {e}")
        return AttackOutcome(
            id=atk.id, title=atk.title,
            error=f"unexpected:{type(e).__name__}",
            duration_ms=(time.perf_counter() - start) * 1000,
        )


async def _read_responses(ctx, target: WidgetTarget) -> str:
    try:
        elements = await ctx.query_selector_all(target.response_selector)
        texts = []
        for el in elements[-10:]:
            try:
                t = await el.inner_text()
                if t:
                    texts.append(t)
            except Exception:
                continue
        return "\n".join(texts)
    except Exception:
        return ""


async def _wait_for_new_response(ctx, target: WidgetTarget, before: str) -> str:
    """Poll until response text changes, with a hard ceiling."""
    deadline = asyncio.get_event_loop().time() + (RESPONSE_WAIT_MS / 1000)
    last = ""
    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(0.6)
        current = await _read_responses(ctx, target)
        if current and current != before:
            last = current
            # Give the bot a beat to finish streaming
            await asyncio.sleep(1.0)
            current = await _read_responses(ctx, target)
            return current[len(before):].strip() if current.startswith(before) else current
        last = current
    return last[len(before):].strip() if last.startswith(before) else last
