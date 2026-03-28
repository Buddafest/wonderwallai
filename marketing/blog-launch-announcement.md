# Introducing Skint Labs: Two AI Products, One Solo Founder, Zero Prior Experience

**Meta description:** Skint Labs launches Jerry The Customer Service Bot and WonderwallAi — an AI customer service platform for Shopify and an open-source AI firewall SDK, both built from scratch by a first-time solo founder.

---

Six months ago, I didn't know how to write a line of code. Today, I'm launching two commercial AI products under a company called Skint Labs. This is the story of how that happened, what I built, and why I think it matters.

## The Idea That Started Everything

I had a simple observation: small Shopify store owners spend hours every day answering the same customer questions. Where's my order? Can I return this? Do you have this in blue? What's the shipping cost to Canada?

These questions have real answers that exist in the store's data. The order status is in Shopify. The return policy is written down. The product catalog has every colour and size listed. Why was a human copying and pasting this information into a chat window?

I decided to build an AI assistant that could actually answer these questions by connecting to the data, not by pattern-matching against an FAQ document. I called it Jerry The Customer Service Bot.

## Building Jerry

Jerry is an AI customer service platform built specifically for Shopify. When a store installs Jerry, it syncs their entire product catalog into a semantic search engine powered by vector embeddings. Customers can search in natural language — asking for "something warm for hiking under $80" returns real, in-stock products that match.

But semantic product search was just the start. Jerry also connects to the Shopify Admin API for real-time order tracking, processes returns and refunds against the store's actual policies, speaks 50+ languages with built-in voice chat, and tracks revenue attribution so store owners can measure exactly what Jerry earns them.

The technical stack is Python and FastAPI on the backend, React and TypeScript for the embeddable chat widget, Groq running Llama 3 for the AI engine, Pinecone for vector storage, and Stripe for billing. It runs on Railway and deploys automatically on every push to main.

I built every piece of it. The conversation engine, the billing system, the OAuth flow, the widget that injects into any Shopify storefront using shadow DOM isolation. Some of it I built well on the first try. Most of it I rebuilt three or four times.

## The Security Wake-Up Call

Then I put Jerry in front of real users, and something I hadn't anticipated happened.

Within the first week, people started trying to break it. Prompt injection attempts, requests to ignore instructions and reveal the system prompt, users treating the e-commerce bot as a free general-purpose AI assistant. And the one that genuinely alarmed me: a user managed to get the LLM to echo back an API key that was present in the context window.

I looked at existing AI security solutions. Hosted API scanners added latency and sent my customers' conversations to third-party servers. Heavy frameworks wanted to replace my entire LLM pipeline. I just needed a function that could tell me if a message was safe, in under 5 milliseconds, without the data leaving my server.

So I built one.

## WonderwallAi: The Firewall That Became a Product

WonderwallAi started as an internal security module inside Jerry. It's a 4-layer protection pipeline:

The **Semantic Router** uses lightweight embeddings to compute cosine similarity between a user's message and a set of allowed topics. You define topics in plain English. It runs locally in under 2ms with zero API calls. This single layer catches the vast majority of off-topic abuse and basic injection attempts.

The **Sentinel Scan** is an LLM-based binary classifier that detects sophisticated injection — the kind that looks on-topic but hides malicious instructions. It only runs on messages that pass the semantic router, so the expensive LLM call is reserved for genuinely ambiguous cases.

The **Egress Filter** scans LLM output for leaked API keys, PII, and canary tokens. The canary token technique is particularly elegant: you inject a unique token into the system prompt and check if it appears in the response. If it does, someone successfully extracted your instructions. Hard block, zero false positives.

The **File Sanitizer** validates uploads by magic bytes and strips EXIF metadata, preventing GPS coordinates and camera data from leaking through image uploads.

After building it for Jerry, I realized every developer deploying an LLM-facing application has this same problem. So I extracted WonderwallAi into its own product, wrote 59 tests, published it on PyPI, open-sourced the SDK under MIT, and built a hosted API for teams that don't want to self-host.

## Why "Skint Labs"

Skint is Australian slang for broke. I started this company with no funding, no team, no technical background, and not much money. The name is a reminder of where this started and a commitment to building tools that are accessible — not just for companies with enterprise budgets.

Both products reflect that philosophy. Jerry's base plan is $299/month, a fraction of what a human support agent costs. WonderwallAi's SDK is completely free and open source, with a hosted API starting at $0/month.

## What I Learned

**AI tools are a genuine equaliser, but they aren't magic.** I used AI extensively to learn programming, debug problems, and generate boilerplate. At some point you need to understand what the code does, why it fails, and how to fix things that AI can't see from a prompt. The tools got me started. The understanding is what let me finish.

**Building in public is terrifying but effective.** Every time I shared progress, I got feedback that changed the direction of the product. The security layer exists because users showed me a vulnerability I hadn't considered. The revenue attribution feature exists because a Shopify store owner told me that was the only metric they cared about.

**Solo founding is lonely but clarifying.** There's no one to argue with about architecture decisions, which means you make them fast. There's also no one to catch your mistakes, which means you learn from them hard. Both of these are features, not bugs.

## What's Next

Skint Labs is soft-launching on March 26, 2026, with a full public launch on April 26. Both products are live and ready for users.

For Jerry, the roadmap includes custom brand voice training, advanced analytics, and multi-store management for agencies. For WonderwallAi, I'm building a monitoring dashboard, adding more LLM provider support for the Sentinel classifier, and exploring Pinecone-backed semantic routing for enterprise deployments.

If you run a Shopify store and you're tired of answering the same questions, try Jerry. If you're building an LLM application and you haven't thought about what happens when users try to jailbreak it, try WonderwallAi. Both of those problems are more urgent than most people realize.

---

**Jerry The Customer Service Bot:** https://jerry.skintlabs.ai | [Live Demo](https://sunsetbot-production.up.railway.app/static/demo.html)

**WonderwallAi:** https://wonderwallai.skintlabs.ai | [GitHub](https://github.com/Buddafest/wonderwallai) | [PyPI](https://pypi.org/project/wonderwallai/)

**Skint Labs:** https://skintlabs.ai

*Built by Louis Constant. First-time founder. Self-taught developer. Turning 40 into a fresh start.*
