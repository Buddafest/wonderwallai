# r/shopify Post

## Title
I built an AI customer service bot that actually connects to your Shopify store (not just a GPT wrapper)

## Body

I've been lurking in this sub for a while and I see the same pain points come up constantly: customer support volume is crushing, "Where Is My Order" tickets are relentless, and most AI chatbot tools just send messages to ChatGPT with your FAQ pasted in.

I built something different. Jerry The Customer Service Bot is an AI assistant that connects directly to your Shopify store through the Admin API. Here's what that actually means in practice:

**Semantic product search, not keyword matching.** A customer can type "I need something warm for hiking, nothing too expensive" and Jerry will search your actual catalog using vector embeddings, filter by price and attributes, and recommend products that are genuinely in stock. It understands size, colour, material, occasion — not just product titles.

**Real order tracking.** Jerry pulls live order data from Shopify. When a customer asks "where's my order #4821," Jerry checks fulfilment status, shipping carrier, and delivery estimates. No scripted "please check your email for tracking" responses.

**Returns processing.** Jerry knows your return policy, checks eligibility windows, and walks customers through the return flow.

**Revenue attribution.** Jerry tracks which conversations lead to purchases within a 24-hour attribution window using Shopify order webhooks. You can see exactly how much revenue Jerry generated in your dashboard. It's not a cost centre — it's measurable.

**Built-in AI security.** Every conversation is protected by a 4-layer AI firewall (my other product, WonderwallAi). Nobody can jailbreak it, use it as a free coding assistant, or extract sensitive data. Within the first week of testing, someone tried to get the LLM to reveal API keys.

**Voice chat and 50+ languages.** Uses the browser's built-in Web Speech API — no extra cost, no external service.

**Full observability — not a black box.** This is the one I'm most proud of and I haven't seen any other Shopify chatbot do it. Jerry doesn't just log what it said — it logs WHY. Every intent classification comes with a confidence score and the matched reasoning. Every product recommendation includes the semantic similarity score. Every escalation logs the trigger and priority. Every LLM call records token counts and latency. You can query your logs and see every decision Jerry made, including decisions you weren't there for. When your AI assistant does something unexpected, you shouldn't have to guess why. You should be able to look it up.

The pricing is $49/mo base (up to 500 conversations), $149/mo Growth (2,000 conversations), $499/mo Elite (unlimited). 7-day free trial on all plans, no credit card required upfront.

I'm a solo founder and this is my first product. I built it because I genuinely think small and mid-size Shopify stores deserve AI support that actually works — not glorified FAQ bots, and not tools that are a black box you can't trust or debug.

Landing page with full details and install: https://jerry.skintlabs.ai

Happy to answer any questions. And if you install it and manage to break it, I genuinely want to know.
