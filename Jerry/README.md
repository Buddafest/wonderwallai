# Jerry The Customer Service Bot

**AI-powered customer service chatbot SaaS for Shopify stores.**

Live at: [sunsetbot-production.up.railway.app](https://sunsetbot-production.up.railway.app)

---

## What It Does

Shopify store owners install Jerry via OAuth. Jerry syncs their product catalog, and their customers get an AI shopping assistant that can:

- Search products semantically ("something for the beach under $50")
- Track orders (Where Is My Order?)
- Handle returns and refunds
- Recommend products with upsell/cross-sell
- Detect frustrated customers and escalate to human support
- Voice chat via browser Web Speech API
- Block prompt injection attacks via WonderwallAi firewall

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python 3.11, FastAPI, WebSocket |
| AI/LLM | Groq API (Llama 3.3 70B) |
| Embeddings | SentenceTransformers (all-MiniLM-L6-v2) |
| Vector DB | Pinecone |
| Database | SQLAlchemy async (SQLite dev / PostgreSQL prod) |
| Sessions | Redis (with in-memory fallback) |
| Auth | JWT (PyJWT) |
| Firewall | WonderwallAi SDK |
| Billing | Stripe (metered subscriptions) |
| Frontend | React 18 + TypeScript + Vite (embeddable widget) |
| Deployment | Railway (auto-deploy on push to main) |

## Project Structure

```
sunsetbot/
├── shopify.app.toml                     # Shopify app config
├── railway.toml                         # Railway deployment config
├── docs/
│   └── index.html                       # Landing page (GitHub Pages)
├── backend/
│   ├── main.py                          # FastAPI app, WebSocket, lifespan
│   ├── Dockerfile                       # Docker build (Railway)
│   ├── requirements.txt                 # Python dependencies
│   ├── static/
│   │   ├── sunsetbot-widget.iife.js     # Built React widget
│   │   ├── dashboard.html               # Store dashboard UI
│   │   └── demo.html                    # Widget demo page
│   └── app/
│       ├── services/
│       │   ├── conversation_engine.py   # AI pipeline (intent → entities → products → LLM → escalation)
│       │   ├── product_intelligence.py  # Semantic search + Pinecone
│       │   ├── shopify_sync.py          # Shopify product sync
│       │   ├── billing_service.py       # Stripe metered billing
│       │   └── analytics_service.py     # Usage tracking + revenue attribution
│       ├── api/
│       │   ├── shopify.py               # OAuth, webhooks, product sync
│       │   ├── billing.py               # Stripe subscriptions + webhooks
│       │   ├── dashboard.py             # Store dashboard API
│       │   └── admin.py                 # Admin panel API
│       ├── core/
│       │   ├── config.py                # Pydantic Settings (all env vars)
│       │   └── security.py              # JWT + HMAC + admin auth
│       └── db/
│           ├── models.py                # Store, ChatSession, SupportResolution, AttributedSale
│           └── engine.py                # Async DB engine + auto-migrations
└── frontend/
    ├── vite.config.ts
    └── src/
        ├── main.tsx                     # Widget entry (shadow DOM)
        └── Widget.tsx                   # React chat widget
```

## Running Locally

```bash
# Backend
cd backend
source venv/bin/activate
python main.py
# → http://localhost:8000
# → http://localhost:8000/docs (Swagger)
# → http://localhost:8000/static/demo.html (widget demo)

# Frontend (if making widget changes)
cd frontend
npm install && npm run build
# → outputs to backend/static/sunsetbot-widget.iife.js
```

## API Endpoints

```
GET  /health                                Health check
GET  /docs                                  Swagger UI

# Shopify
GET  /shopify/install                       Start OAuth flow
GET  /shopify/callback                      OAuth callback
GET  /shopify/widget-token                  Get JWT for widget
POST /shopify/webhooks                      Product/order/app webhooks

# Chat
WS   /ws/chat/{store_id}/{session_id}       WebSocket chat

# Billing
POST /billing/create-subscription           Create Stripe subscription
POST /billing/webhooks                      Stripe webhook handler
GET  /billing/usage/{store_domain}          Usage stats

# Dashboard
GET  /dashboard/{store_domain}/stats        Store stats
GET  /dashboard/{store_domain}/recent-chats Recent conversations

# Admin (X-Admin-API-Key header)
GET  /admin/stores                          All stores
GET  /admin/stats                           Global stats
GET  /admin/stores/{domain}/conversations   Store conversations
```

## Billing

Two plans (AUD):
- **Base:** $299/mo + $0.50/resolution + 1% revenue share
- **Elite:** $1,499/mo + $1.00/resolution + 1% revenue share

Stripe handles subscriptions, metered usage, and webhooks.

## Environment Variables

Required for production:
```
ENVIRONMENT=production
SECRET_KEY=<64+ char random string>
ADMIN_API_KEY=<strong random key>
GROQ_API_KEY=<from console.groq.com>
PINECONE_API_KEY=<from pinecone.io>
SHOPIFY_API_KEY=<from Shopify Partners>
SHOPIFY_API_SECRET=<from Shopify Partners>
STRIPE_SECRET_KEY=<from Stripe dashboard>
STRIPE_WEBHOOK_SECRET=<from Stripe webhook endpoint>
STRIPE_BASE_FLAT_PRICE_ID=<Stripe price ID>
STRIPE_BASE_RESOLUTION_PRICE_ID=<Stripe price ID>
STRIPE_BASE_REVENUE_SHARE_PRICE_ID=<Stripe price ID>
STRIPE_ELITE_FLAT_PRICE_ID=<Stripe price ID>
STRIPE_ELITE_RESOLUTION_PRICE_ID=<Stripe price ID>
STRIPE_ELITE_REVENUE_SHARE_PRICE_ID=<Stripe price ID>
REDIS_URL=<from Railway Redis addon>
CORS_ORIGINS=<comma-separated store domains>
```

## Deployment

Push to `main` triggers Railway auto-deploy:
```bash
git push origin main
```

---

**GitHub:** [SkintLabs/Jerry](https://github.com/SkintLabs/Jerry)
**Landing Page:** [GitHub Pages](https://buddafest.github.io/sunsetbot/)
