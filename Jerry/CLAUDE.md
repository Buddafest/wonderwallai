# CLAUDE.md — Jerry The Customer Service Bot

## What This Project Is

Jerry The Customer Service Bot is an AI-powered customer service chatbot SaaS for Shopify stores. Store owners install via Shopify OAuth, their product catalog syncs automatically, and customers get an intelligent shopping assistant via an embeddable chat widget.

**Deployed:** Railway at `https://sunsetbot-production.up.railway.app`
**Shopify app:** Installed on dev store `sunsetbot.myshopify.com`
**Billing:** Stripe (Base $299/mo, Elite $1,499/mo AUD + metered)

## Tech Stack

- **Backend:** Python 3.11 + FastAPI + WebSocket
- **AI/LLM:** Groq API with `llama-3.3-70b-versatile`
- **Embeddings:** SentenceTransformers (`all-MiniLM-L6-v2`, 384-dim)
- **Vector DB:** Pinecone (with in-memory mock fallback for dev)
- **Database:** SQLAlchemy async — SQLite (dev) / PostgreSQL (production)
- **Sessions:** Redis with 24h TTL (fallback to in-memory if no REDIS_URL)
- **Auth:** JWT (PyJWT) for widget, X-Admin-API-Key for admin endpoints
- **Firewall:** WonderwallAi SDK (`wonderwallai[all]>=0.1.0` from PyPI)
- **Billing:** Stripe subscriptions + metered usage + webhook handler
- **Frontend:** React 18 + TypeScript + Vite — builds to single embeddable IIFE
- **Python venv:** `backend/venv/` (Python 3.11)

## Project Structure

```
sunsetbot/
├── CLAUDE.md                              # THIS FILE
├── shopify.app.toml                       # Shopify app config
├── railway.toml                           # Railway deployment config
├── docs/
│   └── index.html                         # Landing page (GitHub Pages)
├── backend/
│   ├── main.py                            # FastAPI app v4.0.0, WebSocket, lifespan
│   ├── Dockerfile                         # Docker build (PyTorch CPU-only)
│   ├── requirements.txt                   # Python dependencies
│   ├── .env                               # API keys (NEVER commit)
│   ├── sunsetbot.db                       # SQLite database (dev, auto-created)
│   ├── static/
│   │   ├── sunsetbot-widget.iife.js       # Built React widget
│   │   ├── dashboard.html                 # Store dashboard (Golden Hour theme)
│   │   └── demo.html                      # Widget demo page
│   └── app/
│       ├── services/
│       │   ├── conversation_engine.py     # AI pipeline (intent → entities → products → LLM → escalation)
│       │   ├── product_intelligence.py    # Semantic search + Pinecone
│       │   ├── shopify_sync.py            # Shopify product sync service
│       │   ├── billing_service.py         # Stripe metered billing
│       │   └── analytics_service.py       # Usage tracking, revenue attribution
│       ├── api/
│       │   ├── shopify.py                 # Shopify OAuth + webhooks (products, orders, app)
│       │   ├── billing.py                 # Stripe subscriptions + webhook handler
│       │   ├── dashboard.py               # Store dashboard API (stats, recent chats)
│       │   └── admin.py                   # Admin panel API (all stores, global stats)
│       ├── core/
│       │   ├── config.py                  # Pydantic BaseSettings (all env vars)
│       │   └── security.py               # JWT + Shopify HMAC + admin token verification
│       └── db/
│           ├── models.py                  # Store, ChatSession, SupportResolution, AttributedSale
│           └── engine.py                  # Async DB engine + auto-migration
└── frontend/
    ├── vite.config.ts
    └── src/
        ├── main.tsx                       # Widget entry point (shadow DOM mount)
        └── Widget.tsx                     # React chat widget component
```

## How to Run

```bash
# Start backend
cd ~/sunsetbot/backend
source venv/bin/activate
python main.py
# → http://localhost:8000
# → http://localhost:8000/docs (Swagger)
# → http://localhost:8000/static/demo.html (widget demo)
# → http://localhost:8000/static/dashboard.html (store dashboard)

# Build widget (after frontend changes)
cd ~/sunsetbot/frontend
npm run build
# → outputs backend/static/sunsetbot-widget.iife.js

# Deploy (auto on push)
git push origin main
```

## Architecture

```
Store Owner installs via Shopify OAuth
    → /shopify/install → Shopify consent → /shopify/callback
    → Save store + access token to DB
    → Trigger product sync (Shopify REST → CatalogProduct → Pinecone)
    → Register webhooks (products, orders, app/uninstalled)

Customer visits store with widget
    → <script src="sunsetbot-widget.iife.js" data-shop="xxx">
    → Widget mounts in shadow DOM
    → GET /shopify/widget-token → JWT
    → WebSocket: /ws/chat/{store_id}/{session_id}?token=xxx

Chat message flow:
    → WonderwallAi firewall scan (prompt injection protection)
    → Subscription gating (active/trialing only, production mode)
    → ConversationEngine.process_message()
        1. IntentClassifier.classify()      → product_search / order_tracking / etc.
        2. EntityExtractor.extract()        → {colors, price, size, category, ...}
        3. ProductIntelligence.search()     → semantic search + filters
        4. ResponseGenerator.generate()     → Groq LLM → natural language
        5. EscalationHandler.check()        → escalate if frustrated/VIP/keywords
        6. Update sentiment + context
    → WebSocket response: {type, text, products}
    → Analytics tracked (usage, resolutions, revenue attribution)
```

## Critical Patterns

### Branding — Golden Hour Theme
- **"Jerry"** in gold (#d4a040), **"The Customer Service Bot"** in terracotta (#c1666b)
- Colors: Terracotta #c1666b (primary), Gold #d4a040 (accent), Beige #d4b896 (body), Chocolate #4a4032 (structure), Near-black #0c0b0a (bg), Warm white #ede8e0 (headings)
- Typography: Noto Serif (Bold/900) for headings, Inter for body
- Buttons: pill-shaped (border-radius: 100px)

### Services
- All services initialized in `lifespan` context manager (NOT module-level)
- If a service fails to init, server starts in degraded mode
- WonderwallAi firewall uses `ECOMMERCE_TOPICS` pattern and shares embedding model

### Authentication
- Widget JWT: 24h expiry, contains store_id + session_id
- Admin endpoints: `X-Admin-API-Key` header → `verify_admin_token` dependency
- Shopify webhooks: HMAC verification
- WebSocket: JWT required in production, optional in dev

### Subscription Gating
- WebSocket connections rejected with code 4003 if `subscription_status` not in {active, trialing}
- Only enforced when `ENVIRONMENT=production`

### Revenue Attribution
- Orders/create webhook handler checks for chat sessions within last 24 hours
- Only attributes sale to Jerry if recent chat session exists for that store

### Database Migrations
- `engine.py` has `_migrate_add_missing_columns()` — runs ALTER TABLE at startup
- Add new columns to the migrations list for idempotent schema updates

### Settings
- All env vars centralized in `app/core/config.py` — use `get_settings()`
- `settings.is_production` / `settings.is_development` for environment checks
- `settings.shopify_configured` checks if Shopify keys are set

## Shopify Account

- **Dev store:** sunsetbot.myshopify.com
- **App Client ID:** b323444b85e59301f81c74e556dd7efe
- **Distribution:** Custom (install link via Partner dashboard)
- **Webhooks:** products/create, products/update, products/delete, orders/create, refunds/create, app/uninstalled
- **Railway:** sunsetbot-production.up.railway.app (PostgreSQL attached)
- **GitHub:** SkintLabs/Jerry

## Pending Manual Steps

1. Create 6 Stripe prices (Base + Elite × 3 each) and set Railway env vars
2. Create Stripe webhook endpoint → billing/webhooks, set STRIPE_WEBHOOK_SECRET
3. Add Railway Redis addon (auto-sets REDIS_URL)
4. Set strong ADMIN_API_KEY on Railway
5. Run `shopify app deploy` to register orders/create webhook
6. Enable GitHub Pages (Settings → Pages → main branch, /docs folder)
