# Product Hunt Launch — Jerry The Customer Service Bot

## Tagline (under 60 chars)
AI customer service that actually knows your Shopify store

## Description (under 260 chars)
Jerry is an AI customer service bot for Shopify. Syncs your catalog, tracks orders, handles returns, speaks 50+ languages — and logs every agent decision with full context so nothing is a black box. Protected by a 4-layer AI firewall. 7-day free trial.

## Maker's Comment

Hey Product Hunt! I'm Louis, and Jerry is the product I never planned to build.

At 40, with zero software background, I decided to teach myself to code. I had this simple idea: what if a Shopify store could have an AI assistant that actually understood its products — not keyword matching, but real semantic understanding?

Six months later, Jerry exists. I built every piece of it: the FastAPI backend, the React widget, the semantic search engine, the billing system, the AI firewall. Some days I had no idea what I was doing. Most days, honestly. But AI tools gave me superpowers I never expected, and stubbornness filled in the rest.

What makes Jerry different from the dozens of "AI chatbot" tools on the Shopify App Store:

**1. Jerry actually connects to your store.** It syncs your full product catalog into a vector database and understands queries like "something warm for hiking under $80." It pulls real order data from the Shopify Admin API for tracking. It processes returns through your actual policies. It tracks revenue attribution with a 24-hour window.

**2. Jerry is not a black box.** This is the one I'm most proud of. Most AI chatbots log what they said. Jerry logs WHY it made every decision. Every intent classification comes with a confidence score and matched reasoning. Every product recommendation includes the semantic similarity score. Every escalation logs the trigger type, priority, and details. Every LLM call records token counts and latency. You can query: "show me every escalation in the last 7 days" or "why did Jerry recommend Product X" — without needing to have been there when it happened. Agents drift quietly. Intent logging is the early warning layer.

**3. Every conversation is protected.** After launching in production, I watched users try to jailbreak it within the first week. Someone tried to extract an API key from the context window. That led me to build WonderwallAi — an open-source AI firewall that now protects every Jerry conversation.

I'm a solo founder, first-time builder. I made this because small Shopify stores deserve the same quality AI support that enterprise companies get — without enterprise pricing, and without black-box AI they can't debug or trust.

7-day free trial. I'd love your feedback.

## Key Features

- **Semantic Product Search** — Customers search in natural language ("red dress under $60"). Jerry understands price, size, colour, material, and occasion from your real catalog.
- **Order Tracking & Returns** — Real-time order status, shipping estimates, and return processing directly through the Shopify Admin API.
- **Voice Chat & 50+ Languages** — Built-in speech-to-text and text-to-speech. Automatic language detection. Zero extra cost.
- **Revenue Attribution** — 24-hour attribution window links conversations to purchases. Dashboard shows Jerry's exact revenue contribution.
- **Full Agent Observability** — Every decision logged with reasoning, confidence scores, and latency. Intent classification, product recommendations, escalations, LLM calls — all auditable. Not a black box.
- **AI Firewall Protection** — Every conversation protected by WonderwallAi's 4-layer pipeline: semantic routing, prompt injection detection, data leak prevention, and canary tokens.

## Links

- **Install Jerry:** https://jerry.skintlabs.ai
- **GitHub:** https://github.com/SkintLabs/SkintLabs
- **WonderwallAi:** https://wonderwallai.skintlabs.ai
- **Parent Company:** https://skintlabs.ai

## Pricing

- **Base:** $49 USD/mo — up to 500 conversations/month
- **Growth:** $149 USD/mo — up to 2,000 conversations/month
- **Elite:** $499 USD/mo — unlimited conversations + custom brand voice + dedicated support
- **7-day free trial on all plans. No credit card required.**
