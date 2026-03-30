# Product Hunt Launch — WonderwallAi

## Tagline (under 60 chars)
Open-source AI firewall — block prompt injection in <2ms

## Description (under 260 chars)
WonderwallAi is a Python SDK and hosted API that protects LLM applications from prompt injection, data leaks, and off-topic abuse. 4 security layers, <2ms latency, full scan chain logging so every block decision is auditable. MIT licensed. pip install wonderwallai.

## Maker's Comment

Hey Product Hunt! I'm Louis, and I built WonderwallAi after watching real users try to jailbreak my production chatbot.

I run a Shopify AI assistant called Jerry. Within the first week of going live, I saw prompt injection attempts, users treating it like a free coding assistant, and — the one that kept me up at night — someone managed to get the LLM to echo back an API key from the context window.

I looked at every existing solution. Hosted API scanners added 50-200ms latency and sent my customers' conversations to third-party servers. Heavy frameworks wanted to wrap my entire LLM pipeline. I just wanted a function that takes a message and says "safe or not safe" in under 5 milliseconds.

So I built my own. WonderwallAi is a 4-layer pipeline:

1. **Semantic Router** — cosine similarity against allowed topics using local embeddings. Under 2ms. No API call. This alone catches 90% of off-topic abuse.
2. **Sentinel Scan** — LLM binary classifier for sophisticated injection. Only runs after Layer 1 passes.
3. **Egress Filter** — catches leaked API keys, PII, and canary tokens in LLM output.
4. **File Sanitizer** — validates uploads by magic bytes, strips EXIF metadata.

The biggest surprise: off-the-shelf embeddings with a simple cosine similarity threshold catch 90%+ of attacks. I expected to need a fine-tuned classifier. Nope.

**The thing I added recently that I didn't see anywhere else: full scan chain observability.** Every layer decision is logged with the actual reasoning — not just "blocked," but WHY. Semantic router logs all similarity scores including top-3 topic matches. Sentinel scan logs the LLM's decision with token counts and latency. Egress filter logs every violation found. The full pipeline timing is available per request — semantic latency, sentinel latency, egress latency, total. `request_id` is bound to every log line automatically so you can trace any request end-to-end.

Most security tools tell you something was blocked. WonderwallAi tells you exactly why, how long it took, and which layer caught it. That's the difference when you need to tune your configuration or investigate an incident.

I'm 40, self-taught, building my first software products. WonderwallAi started as an internal component and became its own product because I realized every developer building LLM apps faces the same problem.

MIT licensed, 59 tests passing, on PyPI right now. Try it, break it, tell me what I missed.

## Key Features

- **<2ms Latency** — The semantic router runs entirely locally using lightweight embeddings. No external API calls on the fast path. Most attacks never make it past this layer.
- **4-Layer Defence** — Semantic routing, LLM-based injection detection, output scanning (API keys, PII, canary tokens), and file sanitization.
- **Full Scan Chain Logging** — Every layer decision logged with reasoning, confidence scores, and per-layer latency. Every block is auditable. `request_id` propagates through all log lines automatically.
- **3 Lines to Integrate** — `pip install wonderwallai`, define your topics, call `scan_inbound()`. Works with any LLM provider.
- **Canary Token System** — Inject a unique token into the system prompt. If it appears in output, someone extracted your instructions. Hard block, zero false positives.
- **Open Source (MIT)** — Full SDK is free. Hosted API available for teams that don't want to manage infrastructure. Audit log stored per API key.

## Links

- **GitHub:** https://github.com/SkintLabs/SkintLabs
- **PyPI:** https://pypi.org/project/wonderwallai/
- **Landing Page:** https://wonderwallai.skintlabs.ai
- **Parent Company:** https://skintlabs.ai

## Pricing (Hosted API)

- **Free:** 1,000 scans/month, all 4 layers, full audit log
- **Starter:** $29 USD/mo — 50,000 scans/month
- **Pro & Business tiers** available for higher volume
- **Early bird:** First 300 customers get 50% off forever
