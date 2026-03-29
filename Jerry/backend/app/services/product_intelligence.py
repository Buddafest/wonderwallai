"""
================================================================================
Jerry The Customer Service Bot — ProductIntelligence Service
================================================================================
File:     app/services/product_intelligence.py
Version:  1.2.0
Session:  4 (February 2026)
Author:   Built in collaboration with AI assistant

PURPOSE
-------
Manages the product catalog: indexing products into Pinecone for semantic
vector search, and retrieving/re-ranking results based on customer queries.

ARCHITECTURE POSITION
---------------------
ConversationEngine.process_message()
    └─► ProductIntelligence.search()              ← YOU ARE HERE
            ├─► SentenceTransformer.encode()       (generate query embedding)
            ├─► PineconeIndex.query()              (vector similarity search)
            └─► rerank()                           (score + sort results)

CHANGES IN v1.2.0 (Session 4)
-------------------------------
- Fixed: Mock search now filters by color, category, and min_price (was only max_price)
- Fixed: Pinecone filter builder supports price ranges ($gte + $lte) not just $lte
- Carried forward from v1.1.0: pre-computed embeddings, asyncio fixes, thread pools

SETUP CHECKLIST
----------------
1. Pinecone account at https://app.pinecone.io
2. PINECONE_API_KEY in .env
3. Create index: name=sunsetbot-products, dims=384, metric=cosine, cloud=AWS/us-east-1
4. Seed products (see bottom of this file)
================================================================================
"""

import os
import asyncio
import logging
import concurrent.futures
from dataclasses import dataclass, field
from typing import Any, Optional

import numpy as np
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("sunsetbot.product_intelligence")

# ---------------------------------------------------------------------------
# Pinecone client — graceful fallback to mock mode if not installed
# ---------------------------------------------------------------------------
try:
    from pinecone import Pinecone as PineconeClient
    PINECONE_AVAILABLE = True
except ImportError:
    PINECONE_AVAILABLE = False
    logger.warning("pinecone-client not installed — running in MOCK MODE")


# ============================================================================
# CONSTANTS
# ============================================================================

INDEX_NAME      = "sunsetbot-products"
EMBEDDING_MODEL = "all-MiniLM-L6-v2"   # 384-dimensional, fast, free
EMBEDDING_DIM   = 384


# ============================================================================
# DATA MODEL
# ============================================================================

@dataclass
class CatalogProduct:
    """
    A product in the store catalog — the enriched version used inside
    ProductIntelligence. Distinct from the lightweight Product dataclass
    in conversation_engine.py (which is what gets returned to the LLM).
    """
    id: str
    title: str
    price: float
    category: str           = ""
    description: str        = ""
    tags: list              = field(default_factory=list)
    colors: list            = field(default_factory=list)
    sizes: list             = field(default_factory=list)
    materials: list         = field(default_factory=list)
    image_url: Optional[str] = None
    url: Optional[str]      = None
    inventory: int          = 99
    sales_velocity: float   = 0.5    # 0–1, normalized sales rank

    def build_embedding_text(self) -> str:
        """Build rich text for embedding. Title repeated 3x for weight."""
        parts = [
            self.title, self.title, self.title,
            self.description,
            self.category,
            " ".join(self.tags),
            " ".join(f"color {c}" for c in self.colors),
            " ".join(f"size {s}" for s in self.sizes),
            " ".join(f"material {m}" for m in self.materials),
        ]
        return " ".join(p for p in parts if p).strip()

    def to_metadata(self) -> dict:
        """Flatten to dict for Pinecone metadata storage."""
        return {
            "title":     self.title,
            "price":     float(self.price),
            "category":  self.category,
            "tags":      self.tags,
            "colors":    self.colors,
            "inventory": self.inventory,
            "image_url": self.image_url or "",
            "url":       self.url or "",
            "sales_velocity": self.sales_velocity,
        }


# ============================================================================
# PRODUCT INTELLIGENCE — MAIN CLASS
# ============================================================================

class ProductIntelligence:
    """
    Semantic product search layer for Jerry The Customer Service Bot.

    Public API:
        await pi.search(query, store_id, filters, top_k)
        await pi.index_products(products, store_id)
        await pi.delete_product(product_id, store_id)
    """

    def __init__(self):
        # --- Embedding model -----------------------------------------------
        logger.info("Loading embedding model — first run may take 30s...")
        try:
            from sentence_transformers import SentenceTransformer
            self.embedding_model = SentenceTransformer(EMBEDDING_MODEL)
            logger.info("Embedding model loaded.")
        except Exception as e:
            logger.error(
                f"Failed to load embedding model '{EMBEDDING_MODEL}': {e}. "
                "Product search will be unavailable."
            )
            self.embedding_model = None

        # --- Thread pools --------------------------------------------------
        cpu_count = os.cpu_count() or 1
        self._embedding_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=min(4, cpu_count),
            thread_name_prefix="embedding",
        )
        self._pinecone_executor = concurrent.futures.ThreadPoolExecutor(
            max_workers=8,
            thread_name_prefix="pinecone",
        )

        # --- Pinecone ------------------------------------------------------
        self._pinecone_index = None
        self._mock_mode      = True

        api_key = os.getenv("PINECONE_API_KEY", "")
        if PINECONE_AVAILABLE and api_key and api_key != "your_pinecone_key_here":
            try:
                pc = PineconeClient(api_key=api_key)
                existing = [idx.name for idx in pc.list_indexes()]

                if INDEX_NAME in existing:
                    self._pinecone_index = pc.Index(INDEX_NAME)
                    self._mock_mode      = False
                    logger.info(f"Connected to Pinecone index '{INDEX_NAME}'")
                else:
                    logger.warning(
                        f"Pinecone index '{INDEX_NAME}' not found. "
                        "Create it in the Pinecone dashboard. "
                        "Running in MOCK MODE."
                    )
            except Exception as e:
                logger.error(f"Pinecone connection failed: {e} — falling back to MOCK MODE")
        else:
            logger.info("No Pinecone API key — running in MOCK MODE.")

        # Product cache + pre-computed embeddings for mock mode
        self._product_cache: dict[str, CatalogProduct] = {}
        self._product_embeddings: dict[str, np.ndarray] = {}

        # Seed demo catalog
        self._seed_mock_catalog()

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    async def search(
        self,
        query: str,
        store_id: str,
        filters: Optional[dict] = None,
        top_k: int = 5,
    ) -> list:
        """Semantic product search — primary method called by ConversationEngine."""
        if self.embedding_model is None:
            logger.error("Search called but embedding model not loaded")
            return []

        if self._mock_mode:
            return await self._mock_search(query, filters, top_k)

        return await self._pinecone_search(query, store_id, filters, top_k)

    async def index_products(
        self,
        products: list[CatalogProduct],
        store_id: str,
    ) -> int:
        """Index products into Pinecone (upsert — safe to re-run)."""
        if self._mock_mode:
            for p in products:
                self._product_cache[p.id] = p
            # Pre-compute embeddings for mock search
            await self._precompute_embeddings(products)
            return len(products)

        return await self._upsert_to_pinecone(products, store_id)

    async def delete_product(self, product_id: str, store_id: str) -> None:
        """Remove a product from the index."""
        self._product_cache.pop(product_id, None)
        self._product_embeddings.pop(product_id, None)

        if not self._mock_mode and self._pinecone_index:
            try:
                self._pinecone_index.delete(ids=[product_id], namespace=store_id)
                logger.info(f"Deleted product {product_id} from Pinecone [{store_id}]")
            except Exception as e:
                logger.error(f"Failed to delete product {product_id}: {e}")

    # =========================================================================
    # EMBEDDING PRE-COMPUTATION
    # =========================================================================

    async def _precompute_embeddings(self, products: list[CatalogProduct]) -> None:
        """Pre-compute and cache embeddings for a list of products."""
        if self.embedding_model is None:
            return

        texts = [p.build_embedding_text() for p in products]
        loop = asyncio.get_running_loop()

        # Batch encode all products at once
        embeddings = await loop.run_in_executor(
            self._embedding_executor,
            self.embedding_model.encode, texts
        )

        for i, product in enumerate(products):
            self._product_embeddings[product.id] = embeddings[i]

        logger.info(f"Pre-computed embeddings for {len(products)} products.")

    # =========================================================================
    # PINECONE SEARCH (real mode)
    # =========================================================================

    async def _pinecone_search(
        self,
        query: str,
        store_id: str,
        filters: Optional[dict],
        top_k: int,
    ) -> list:
        loop = asyncio.get_running_loop()

        # Embed query
        query_vector = await loop.run_in_executor(
            self._embedding_executor, self.embedding_model.encode, query
        )

        # Build filter
        pinecone_filter = self._build_pinecone_filter(filters)

        # Query Pinecone with timeout
        try:
            results = await asyncio.wait_for(
                loop.run_in_executor(
                    self._pinecone_executor,
                    lambda: self._pinecone_index.query(
                        vector=query_vector.tolist(),
                        top_k=top_k * 2,
                        namespace=store_id,
                        filter=pinecone_filter if pinecone_filter else None,
                        include_metadata=True,
                    ),
                ),
                timeout=10.0,
            )
        except asyncio.TimeoutError:
            logger.error("Pinecone query timed out — returning empty results")
            return []
        except Exception as e:
            logger.error(f"Pinecone query failed: {e} — returning empty results")
            return []

        # Convert to Product objects
        from app.services.conversation_engine import Product as EngineProduct

        products = []
        for match in results.matches:
            meta = match.metadata or {}
            products.append(
                EngineProduct(
                    id=match.id,
                    title=meta.get("title", "Unknown Product"),
                    price=float(meta.get("price", 0)),
                    category=meta.get("category", ""),
                    description="",
                    image_url=meta.get("image_url") or None,
                    url=meta.get("url") or None,
                    inventory=int(meta.get("inventory", 99)),
                    relevance_score=float(match.score),
                )
            )

        ranked = self._rerank(products, filters)
        return ranked[:top_k]

    async def _upsert_to_pinecone(
        self, products: list[CatalogProduct], store_id: str
    ) -> int:
        """Embed products in batches and upsert to Pinecone."""
        loop       = asyncio.get_running_loop()
        batch_size = 100
        indexed    = 0

        for i in range(0, len(products), batch_size):
            batch = products[i : i + batch_size]
            texts = [p.build_embedding_text() for p in batch]

            embeddings = await loop.run_in_executor(
                self._embedding_executor, self.embedding_model.encode, texts
            )

            vectors = [
                {
                    "id":       p.id,
                    "values":   embeddings[j].tolist(),
                    "metadata": p.to_metadata(),
                }
                for j, p in enumerate(batch)
            ]

            try:
                self._pinecone_index.upsert(vectors=vectors, namespace=store_id)
                indexed += len(batch)
                logger.info(f"Upserted batch {i//batch_size + 1} ({len(batch)} products) → [{store_id}]")

                for p in batch:
                    self._product_cache[p.id] = p

            except Exception as e:
                logger.error(f"Upsert failed for batch starting at {i}: {e}")

        return indexed

    # =========================================================================
    # MOCK SEARCH (uses pre-computed embeddings — fast)
    # =========================================================================

    async def _mock_search(
        self,
        query: str,
        filters: Optional[dict],
        top_k: int,
    ) -> list:
        """
        In-memory semantic search using pre-computed product embeddings.
        Only the query needs to be embedded per search — products are cached.
        """
        if not self._product_cache:
            return []

        loop = asyncio.get_running_loop()

        # Embed the query (only embedding call per search)
        query_vector = await loop.run_in_executor(
            self._embedding_executor, self.embedding_model.encode, query
        )

        # Score each cached product using pre-computed embeddings
        scored = []
        for product in self._product_cache.values():
            # Hard filters — skip products that don't match
            if product.inventory <= 0:
                continue

            if filters:
                if "max_price" in filters and product.price > filters["max_price"]:
                    continue
                if "min_price" in filters and product.price < filters["min_price"]:
                    continue
                if "category" in filters:
                    # Use category_group if available (e.g. shoes → [shoe, boot, sneaker, sandal])
                    allowed_cats = filters.get("category_group", [filters["category"]])
                    product_cat = product.category.lower().rstrip("s")
                    if not any(ac.lower() in product_cat or product_cat in ac.lower() for ac in allowed_cats):
                        continue
                if "colors" in filters:
                    product_colors = {c.lower() for c in product.colors}
                    requested_colors = {c.lower() for c in filters["colors"]}
                    if not product_colors & requested_colors:
                        continue

            # Use pre-computed embedding
            product_vector = self._product_embeddings.get(product.id)
            if product_vector is None:
                continue

            similarity = self._cosine_similarity(query_vector, product_vector)
            scored.append((product, similarity))

        scored.sort(key=lambda x: x[1], reverse=True)
        candidates = scored[: top_k * 2]

        from app.services.conversation_engine import Product as EngineProduct

        products = [
            EngineProduct(
                id=p.id,
                title=p.title,
                price=p.price,
                category=p.category,
                description=p.description,
                image_url=p.image_url,
                url=p.url,
                inventory=p.inventory,
                relevance_score=score,
            )
            for p, score in candidates
        ]

        ranked = self._rerank(products, filters)
        return ranked[:top_k]

    # =========================================================================
    # RE-RANKING
    # =========================================================================

    def _rerank(self, products: list, filters: Optional[dict]) -> list:
        """
        Multi-factor re-ranking:
            60% semantic relevance, 20% inventory, 10% sales velocity, 10% price match
        """
        for product in products:
            score = 0.0

            score += product.relevance_score * 0.6

            inv = product.inventory
            if inv > 10:
                score += 0.20
            elif inv > 0:
                score += 0.20 * (inv / 10)

            cached = self._product_cache.get(product.id)
            velocity = cached.sales_velocity if cached else 0.5
            score += velocity * 0.10

            if filters and "max_price" in filters:
                if product.price <= filters["max_price"]:
                    score += 0.10
            else:
                score += 0.10

            product.final_score = score

        products.sort(key=lambda p: p.final_score, reverse=True)
        return products

    # =========================================================================
    # FILTER BUILDER
    # =========================================================================

    def _build_pinecone_filter(self, filters: Optional[dict]) -> dict:
        """Convert entity extractor output to Pinecone filter format."""
        if not filters:
            return {"inventory": {"$gt": 0}}

        pf: dict[str, Any] = {}

        if "max_price" in filters and "min_price" in filters:
            pf["price"] = {
                "$gte": float(filters["min_price"]),
                "$lte": float(filters["max_price"]),
            }
        elif "max_price" in filters:
            pf["price"] = {"$lte": float(filters["max_price"])}
        elif "min_price" in filters:
            pf["price"] = {"$gte": float(filters["min_price"])}

        if "colors" in filters:
            pf["colors"] = {"$in": filters["colors"]}

        if "category_group" in filters:
            # Match any category in the group (e.g. shoes → [shoe, boot, sneaker, sandal])
            pf["category"] = {"$in": filters["category_group"]}
        elif "category" in filters:
            pf["category"] = {"$eq": filters["category"]}

        pf["inventory"] = {"$gt": 0}

        return pf

    # =========================================================================
    # UTILITIES
    # =========================================================================

    @staticmethod
    def _cosine_similarity(vec_a: np.ndarray, vec_b: np.ndarray) -> float:
        """Compute cosine similarity between two numpy arrays."""
        dot  = float(np.dot(vec_a, vec_b))
        norm = float(np.linalg.norm(vec_a) * np.linalg.norm(vec_b))
        return dot / norm if norm > 0 else 0.0

    # =========================================================================
    # DEMO PRODUCT CATALOG
    # =========================================================================

    def _seed_mock_catalog(self):
        """Populate in-memory cache with 20 demo products and pre-compute embeddings."""
        demo_products = [
            CatalogProduct(
                id="prod-001", title="Classic Leather Chelsea Boot", price=129.99,
                category="boots",
                description="Premium pull-on ankle boot in smooth leather with elastic side panels. Rubber sole for all-day comfort.",
                tags=["boots", "leather", "ankle boot", "chelsea", "pull-on"],
                colors=["black", "brown", "tan"],
                sizes=["6", "7", "8", "9", "10", "11"],
                materials=["leather"],
                image_url="https://via.placeholder.com/300x300?text=Chelsea+Boot",
                url="https://demo-store.myshopify.com/products/chelsea-boot",
                inventory=45, sales_velocity=0.85,
            ),
            CatalogProduct(
                id="prod-002", title="Waterproof Trail Running Shoe", price=94.99,
                category="shoes",
                description="Technical trail runner with GORE-TEX waterproofing, aggressive lugs for grip, and responsive cushioning.",
                tags=["shoes", "running", "trail", "waterproof", "outdoor", "athletic"],
                colors=["gray", "blue", "orange"],
                sizes=["7", "8", "9", "10", "11", "12"],
                materials=["synthetic", "rubber"],
                image_url="https://via.placeholder.com/300x300?text=Trail+Shoe",
                url="https://demo-store.myshopify.com/products/trail-shoe",
                inventory=78, sales_velocity=0.90,
            ),
            CatalogProduct(
                id="prod-003", title="Suede Block-Heel Ankle Boot", price=109.00,
                category="boots",
                description="Fashion-forward ankle boot with a stable 3-inch block heel, suede upper, and cushioned footbed.",
                tags=["boots", "suede", "heel", "ankle boot", "fashion", "women"],
                colors=["tan", "black", "red"],
                sizes=["5", "6", "7", "8", "9", "10"],
                materials=["suede"],
                image_url="https://via.placeholder.com/300x300?text=Ankle+Boot",
                url="https://demo-store.myshopify.com/products/block-heel-boot",
                inventory=22, sales_velocity=0.70,
            ),
            CatalogProduct(
                id="prod-004", title="Canvas Low-Top Sneaker", price=44.99,
                category="sneakers",
                description="Casual everyday sneaker in classic canvas. Rubber sole, cushioned insole, available in 12 colours.",
                tags=["sneakers", "canvas", "casual", "everyday", "low-top"],
                colors=["white", "black", "red", "blue", "pink"],
                sizes=["5", "6", "7", "8", "9", "10", "11", "12"],
                materials=["canvas", "rubber"],
                image_url="https://via.placeholder.com/300x300?text=Canvas+Sneaker",
                url="https://demo-store.myshopify.com/products/canvas-sneaker",
                inventory=120, sales_velocity=0.95,
            ),
            CatalogProduct(
                id="prod-005", title="Floral Wrap Midi Dress", price=59.99,
                category="dresses",
                description="Effortless wrap dress in lightweight rayon with a vintage floral print. Adjustable tie waist, V-neckline.",
                tags=["dresses", "floral", "midi", "wrap", "summer", "women"],
                colors=["red", "blue", "green"],
                sizes=["XS", "S", "M", "L", "XL"],
                materials=["rayon"],
                image_url="https://via.placeholder.com/300x300?text=Floral+Dress",
                url="https://demo-store.myshopify.com/products/floral-wrap-dress",
                inventory=34, sales_velocity=0.80,
            ),
            CatalogProduct(
                id="prod-006", title="Slim-Fit Stretch Chino", price=69.99,
                category="pants",
                description="Modern slim-fit chino with 2% elastane for unrestricted movement. Wrinkle-resistant, machine washable.",
                tags=["pants", "chino", "slim", "stretch", "office", "men"],
                colors=["navy", "khaki", "black", "gray"],
                sizes=["28", "30", "32", "34", "36", "38"],
                materials=["cotton", "elastane"],
                image_url="https://via.placeholder.com/300x300?text=Chino",
                url="https://demo-store.myshopify.com/products/slim-chino",
                inventory=65, sales_velocity=0.75,
            ),
            CatalogProduct(
                id="prod-007", title="Oversized Merino Wool Sweater", price=119.00,
                category="sweaters",
                description="Luxuriously soft oversized sweater knitted from 100% Merino wool. Ribbed cuffs and hem, drop shoulders.",
                tags=["sweaters", "wool", "merino", "oversized", "cosy", "winter"],
                colors=["cream", "gray", "camel", "black"],
                sizes=["S", "M", "L", "XL"],
                materials=["wool"],
                image_url="https://via.placeholder.com/300x300?text=Wool+Sweater",
                url="https://demo-store.myshopify.com/products/merino-sweater",
                inventory=28, sales_velocity=0.65,
            ),
            CatalogProduct(
                id="prod-008", title="High-Rise Skinny Jeans", price=79.99,
                category="jeans",
                description="High-rise skinny with 4-way stretch denim. Five-pocket styling.",
                tags=["jeans", "skinny", "high-rise", "denim", "stretch", "women"],
                colors=["blue", "black", "white"],
                sizes=["24", "25", "26", "27", "28", "29", "30"],
                materials=["denim", "elastane"],
                image_url="https://via.placeholder.com/300x300?text=Skinny+Jeans",
                url="https://demo-store.myshopify.com/products/skinny-jeans",
                inventory=55, sales_velocity=0.88,
            ),
            CatalogProduct(
                id="prod-009", title="Linen Button-Down Shirt", price=54.99,
                category="shirts",
                description="Breathable summer shirt in 100% Irish linen. Regular fit, chest pocket, pearlescent buttons.",
                tags=["shirts", "linen", "summer", "button-down", "men"],
                colors=["white", "blue", "pink", "sage"],
                sizes=["S", "M", "L", "XL", "XXL"],
                materials=["linen"],
                image_url="https://via.placeholder.com/300x300?text=Linen+Shirt",
                url="https://demo-store.myshopify.com/products/linen-shirt",
                inventory=42, sales_velocity=0.72,
            ),
            CatalogProduct(
                id="prod-010", title="Satin Slip Midi Dress", price=89.99,
                category="dresses",
                description="Sleek satin slip dress with adjustable spaghetti straps and a bias-cut hem.",
                tags=["dresses", "satin", "midi", "slip", "evening", "party", "women"],
                colors=["black", "champagne", "red", "green"],
                sizes=["XS", "S", "M", "L"],
                materials=["satin"],
                image_url="https://via.placeholder.com/300x300?text=Satin+Dress",
                url="https://demo-store.myshopify.com/products/satin-slip-dress",
                inventory=19, sales_velocity=0.78,
            ),
            CatalogProduct(
                id="prod-011", title="Pebbled Leather Tote Bag", price=149.00,
                category="bags",
                description="Spacious tote in pebbled full-grain leather. Interior zip pocket, magnetic snap closure.",
                tags=["bags", "tote", "leather", "work", "everyday"],
                colors=["black", "tan", "brown"],
                sizes=[], materials=["leather"],
                image_url="https://via.placeholder.com/300x300?text=Tote+Bag",
                url="https://demo-store.myshopify.com/products/leather-tote",
                inventory=31, sales_velocity=0.82,
            ),
            CatalogProduct(
                id="prod-012", title="Silk Square Scarf", price=39.99,
                category="accessories",
                description="Versatile 70cm scarf in 100% silk with hand-rolled edges and an abstract botanical print.",
                tags=["accessories", "scarf", "silk", "gift", "women"],
                colors=["blue", "pink", "orange", "green"],
                sizes=[], materials=["silk"],
                image_url="https://via.placeholder.com/300x300?text=Silk+Scarf",
                url="https://demo-store.myshopify.com/products/silk-scarf",
                inventory=60, sales_velocity=0.60,
            ),
            CatalogProduct(
                id="prod-013", title="Minimalist Leather Belt", price=34.99,
                category="accessories",
                description="Full-grain leather dress belt with a matte silver roller buckle. 1.25-inch width.",
                tags=["accessories", "belt", "leather", "men", "women"],
                colors=["black", "brown"],
                sizes=["S", "M", "L", "XL"],
                materials=["leather"],
                image_url="https://via.placeholder.com/300x300?text=Leather+Belt",
                url="https://demo-store.myshopify.com/products/leather-belt",
                inventory=85, sales_velocity=0.55,
            ),
            CatalogProduct(
                id="prod-014", title="Stainless Steel Minimalist Watch", price=199.00,
                category="watches",
                description="Swiss quartz movement, sapphire crystal glass, 40mm stainless steel case, 5ATM water resistance.",
                tags=["watches", "stainless steel", "minimalist", "gift", "unisex"],
                colors=["silver", "gold", "rose gold"],
                sizes=[], materials=["stainless steel"],
                image_url="https://via.placeholder.com/300x300?text=Watch",
                url="https://demo-store.myshopify.com/products/minimalist-watch",
                inventory=14, sales_velocity=0.68,
            ),
            CatalogProduct(
                id="prod-015", title="Wool Knit Beanie", price=24.99,
                category="hats",
                description="Chunky-knit beanie in a cosy wool-acrylic blend. Slouchy fit, fold-up cuff.",
                tags=["hats", "beanie", "winter", "knit", "unisex"],
                colors=["black", "gray", "red", "blue", "cream"],
                sizes=["One Size"], materials=["wool", "acrylic"],
                image_url="https://via.placeholder.com/300x300?text=Beanie",
                url="https://demo-store.myshopify.com/products/knit-beanie",
                inventory=110, sales_velocity=0.70,
            ),
            CatalogProduct(
                id="prod-016", title="Quick-Dry Hiking Shorts", price=49.99,
                category="shorts",
                description="Lightweight nylon hiking shorts with DWR coating, 4 pockets, built-in UPF 30.",
                tags=["shorts", "hiking", "outdoor", "active", "quick-dry", "men"],
                colors=["khaki", "navy", "gray"],
                sizes=["S", "M", "L", "XL", "XXL"],
                materials=["nylon"],
                image_url="https://via.placeholder.com/300x300?text=Hiking+Shorts",
                url="https://demo-store.myshopify.com/products/hiking-shorts",
                inventory=48, sales_velocity=0.73,
            ),
            CatalogProduct(
                id="prod-017", title="Yoga High-Waist Legging", price=64.99,
                category="leggings",
                description="Buttery-soft 4-way stretch fabric. High-waist compressive fit, hidden waistband pocket, squat-proof.",
                tags=["leggings", "yoga", "active", "high-waist", "gym", "women"],
                colors=["black", "gray", "navy", "purple"],
                sizes=["XS", "S", "M", "L", "XL"],
                materials=["polyester", "elastane"],
                image_url="https://via.placeholder.com/300x300?text=Leggings",
                url="https://demo-store.myshopify.com/products/yoga-leggings",
                inventory=92, sales_velocity=0.93,
            ),
            CatalogProduct(
                id="prod-018", title="Packable Down Puffer Jacket", price=179.00,
                category="jackets",
                description="700-fill RDS-certified down jacket that packs into its own pocket. Windproof, water-resistant.",
                tags=["jackets", "down", "puffer", "winter", "packable", "travel"],
                colors=["black", "navy", "red"],
                sizes=["XS", "S", "M", "L", "XL", "XXL"],
                materials=["nylon", "down"],
                image_url="https://via.placeholder.com/300x300?text=Puffer+Jacket",
                url="https://demo-store.myshopify.com/products/puffer-jacket",
                inventory=37, sales_velocity=0.85,
            ),
            CatalogProduct(
                id="prod-019", title="Bamboo Crew-Neck T-Shirt", price=29.99,
                category="tops",
                description="Super-soft 95% bamboo viscose tee. Naturally moisture-wicking, breathable, and eco-friendly.",
                tags=["tops", "t-shirt", "bamboo", "sustainable", "everyday", "unisex"],
                colors=["white", "black", "gray", "green", "blue"],
                sizes=["XS", "S", "M", "L", "XL", "XXL"],
                materials=["bamboo", "elastane"],
                image_url="https://via.placeholder.com/300x300?text=Bamboo+Tee",
                url="https://demo-store.myshopify.com/products/bamboo-tee",
                inventory=145, sales_velocity=0.88,
            ),
            CatalogProduct(
                id="prod-020", title="Woven Straw Sun Hat", price=32.99,
                category="hats",
                description="Classic wide-brim straw hat with a grosgrain ribbon trim. Adjustable inner drawstring. UPF 50+.",
                tags=["hats", "sun hat", "straw", "summer", "beach", "women"],
                colors=["natural", "black"],
                sizes=["S/M", "L/XL"],
                materials=["straw"],
                image_url="https://via.placeholder.com/300x300?text=Sun+Hat",
                url="https://demo-store.myshopify.com/products/sun-hat",
                inventory=6, sales_velocity=0.62,
            ),
        ]

        for product in demo_products:
            self._product_cache[product.id] = product

        # Pre-compute embeddings synchronously at startup
        if self.embedding_model is not None:
            texts = [p.build_embedding_text() for p in demo_products]
            embeddings = self.embedding_model.encode(texts)
            for i, product in enumerate(demo_products):
                self._product_embeddings[product.id] = embeddings[i]
            logger.info(f"Seeded {len(demo_products)} demo products with pre-computed embeddings.")
        else:
            logger.warning(f"Seeded {len(demo_products)} demo products (no embeddings — model not loaded).")


# ============================================================================
# STANDALONE SEED SCRIPT
# ============================================================================

async def seed_demo_products():
    """Index the 20 demo products into Pinecone. Run once after creating the index."""
    print("\n" + "="*60)
    print("  Jerry The Customer Service Bot — Seeding Demo Products into Pinecone")
    print("="*60 + "\n")

    pi = ProductIntelligence()

    if pi._mock_mode:
        print("Running in MOCK MODE — Pinecone not connected.")
        print("Products are in-memory only (not persisted).\n")
    else:
        print(f"Indexing {len(pi._product_cache)} products into Pinecone...")
        products = list(pi._product_cache.values())
        count    = await pi.index_products(products, store_id="demo-store")
        print(f"Indexed {count} products into Pinecone index '{INDEX_NAME}'")

    print("\nRunning test search: 'waterproof boots under $150'")
    results = await pi.search(
        query    = "waterproof boots under $150",
        store_id = "demo-store",
        filters  = {"max_price": 150},
        top_k    = 3,
    )

    print(f"\nTop {len(results)} results:")
    for i, r in enumerate(results, 1):
        print(f"  {i}. {r.title} — ${r.price:.2f} (score: {r.final_score:.3f})")

    print("\nSeed complete.\n")


if __name__ == "__main__":
    asyncio.run(seed_demo_products())
