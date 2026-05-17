"""
Chat-widget detection for the headless prober.

Each known widget vendor has a fingerprint (DOM selector + iframe pattern)
and a strategy for opening the widget, finding its input, typing, and reading
the response.

For sites we don't recognise, the generic detector looks for any visible input
that has nearby "chat" / "message" / "ask" / "type" wording.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class WidgetTarget:
    """How to interact with a detected chat widget."""
    vendor: str                       # "intercom" | "crisp" | "drift" | "tidio" | "tawkto" | "generic"
    open_selector: Optional[str]      # selector to click to open the widget (None if always open)
    iframe_selector: Optional[str]    # CSS selector for the widget's iframe, if iframed
    input_selector: str               # selector for the message input (inside iframe if iframed)
    send_strategy: str                # "enter_key" | "click_send"
    send_selector: Optional[str]      # selector for send button if send_strategy=click_send
    response_selector: str            # selector matching bot response messages (inside iframe if iframed)


# Known-vendor fingerprints. Order matters: more specific first.
KNOWN_WIDGETS: list[tuple[str, WidgetTarget]] = [
    (
        # Intercom Messenger
        "iframe[name='intercom-messenger-frame'], #intercom-container, .intercom-launcher",
        WidgetTarget(
            vendor="intercom",
            open_selector=".intercom-launcher, [aria-label='Open Intercom Messenger']",
            iframe_selector="iframe[name='intercom-messenger-frame']",
            input_selector="textarea[placeholder*='message' i], textarea[name='message'], .intercom-composer-textarea",
            send_strategy="enter_key",
            send_selector=None,
            response_selector=".intercom-comment, [data-testid='admin-message'], .intercom-message-admin",
        ),
    ),
    (
        # Crisp
        "#crisp-chatbox, iframe[src*='client.crisp.chat']",
        WidgetTarget(
            vendor="crisp",
            open_selector="a.cc-1xry, .cc-unooo, [aria-label*='Crisp']",
            iframe_selector="iframe[src*='client.crisp.chat']",
            input_selector="textarea, [contenteditable='true']",
            send_strategy="enter_key",
            send_selector=None,
            response_selector=".cc-1ada .cc-1asuq, [data-from='operator']",
        ),
    ),
    (
        # Drift
        "iframe[id^='drift-frame-chat'], #drift-widget",
        WidgetTarget(
            vendor="drift",
            open_selector="iframe[id^='drift-frame-controller'], [aria-label*='Drift']",
            iframe_selector="iframe[id^='drift-frame-chat']",
            input_selector="textarea[data-qa='message-input'], textarea",
            send_strategy="enter_key",
            send_selector=None,
            response_selector="[data-qa='message-bubble'][data-from='bot'], .drift-message-incoming",
        ),
    ),
    (
        # Tidio
        "#tidio-chat, iframe[id='tidio-chat-iframe']",
        WidgetTarget(
            vendor="tidio",
            open_selector="#tidio-chat-iframe, [aria-label*='Tidio']",
            iframe_selector="iframe[id='tidio-chat-iframe']",
            input_selector="textarea[data-testid='message-input'], textarea",
            send_strategy="enter_key",
            send_selector=None,
            response_selector="[data-testid='message-from-operator'], .message--operator",
        ),
    ),
    (
        # Tawk.to
        "iframe[title='chat widget'], iframe[src*='tawk.to']",
        WidgetTarget(
            vendor="tawkto",
            open_selector="iframe[src*='tawk.to']",
            iframe_selector="iframe[src*='tawk.to/chat/']",
            input_selector="textarea#message, textarea[placeholder*='Type' i]",
            send_strategy="enter_key",
            send_selector=None,
            response_selector=".message.agent, [class*='agent-message']",
        ),
    ),
]


GENERIC_INPUT_HINTS = [
    "placeholder*='message' i",
    "placeholder*='ask' i",
    "placeholder*='type' i",
    "placeholder*='chat' i",
    "aria-label*='message' i",
    "aria-label*='chat' i",
    "name='message'",
]


def generic_input_selectors() -> list[str]:
    """
    CSS selectors for likely chat inputs on sites with no recognised vendor.
    Tried in order; first hit wins.
    """
    selectors = []
    for hint in GENERIC_INPUT_HINTS:
        selectors.append(f"textarea[{hint}]")
        selectors.append(f"input[type='text'][{hint}]")
    return selectors
