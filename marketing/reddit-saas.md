# r/SaaS Post

## Title
I'm 40, self-taught, and just launched two AI products as a solo founder. Here's what I built and what I learned.

## Body

Six months ago I couldn't write a line of code. Today I'm launching two SaaS products built entirely by me with the help of AI development tools. I wanted to share the journey and get honest feedback.

**The products:**

**1. Jerry The Customer Service Bot** (jerry.skintlabs.ai) — An AI customer service assistant for Shopify stores. Not another chatbot wrapper that sends messages to GPT. Jerry connects to your actual Shopify store: it syncs your product catalog into a semantic search engine, pulls live order data for tracking, processes returns through your real policies, and speaks 50+ languages with built-in voice chat.

Pricing: $299/mo base + performance billing. You only pay more when Jerry earns you more.

**2. WonderwallAi** (wonderwallai.skintlabs.ai) — An open-source AI firewall SDK for LLM applications. I built this after watching users try to jailbreak Jerry in production. Someone managed to extract an API key from the LLM's context window during the first week. WonderwallAi sits between your users and your LLM with 4 protection layers, blocking prompt injection in under 2ms.

Open source (MIT), on PyPI, free tier available on the hosted API.

**What I learned building both:**

- Building two products simultaneously as a solo founder is a bad idea that I'd do again. WonderwallAi started as an internal security module for Jerry, and I extracted it into its own product because the problem it solves is universal. The upside is they feed each other — Jerry is the proof that WonderwallAi works in production.

- Pricing is genuinely the hardest part. I changed currencies (AUD to USD), restructured tiers, and agonised over every number. I'm still not sure I got it right.

- The loneliest part of being a solo founder isn't the work. It's having nobody to sanity-check your decisions. You just have to ship and see what the market says.

**The stack:**
- Backend: Python, FastAPI, Groq (Llama 3), Pinecone, SentenceTransformers, Stripe
- Frontend: React, TypeScript, Vite (embeddable chat widget in shadow DOM)
- Hosting: Railway
- Firewall: WonderwallAi (my own product eating my own dog food)

Both products are live. I'd genuinely appreciate feedback on the landing pages, the positioning, the pricing — anything. This is my first time doing any of this, and I know there are things I'm missing.

**Links:**
- Jerry: https://jerry.skintlabs.ai
- WonderwallAi: https://wonderwallai.skintlabs.ai
- WonderwallAi GitHub: https://github.com/Buddafest/wonderwallai
- Parent company: https://skintlabs.ai (Skint Labs)
