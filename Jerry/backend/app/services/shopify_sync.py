"""
================================================================================
Jerry The Customer Service Bot — Shopify Product Sync Service
================================================================================
File:     app/services/shopify_sync.py
Version:  1.0.0
Session:  5 (February 2026)

PURPOSE
-------
Syncs product catalog from a Shopify store into Jerry The Customer Service Bot's search index.

- Full sync: Fetches all products via Shopify REST API (paginated)
- Webhook sync: Processes individual product create/update/delete events
- Converts Shopify product data → CatalogProduct → ProductIntelligence.index_products()

SHOPIFY REST API
-----------------
- Uses Admin REST API (not GraphQL) for simplicity
- Pagination via Link header (cursor-based)
- Max 250 products per page
- Rate limit: 2 requests/sec (handled with backoff)
================================================================================
"""

import asyncio
import logging
import re
from datetime import datetime
from typing import Optional

import httpx
from sqlalchemy import select

from app.core.config import get_settings
from app.db.engine import get_db
from app.db.models import Store
from app.services.product_intelligence import CatalogProduct

logger = logging.getLogger("sunsetbot.shopify_sync")


class ShopifySyncService:
    """
    Fetches and syncs products from Shopify into Jerry The Customer Service Bot's vector index.
    """

    def __init__(self):
        self.settings = get_settings()
        self.api_version = self.settings.shopify_api_version

    # =========================================================================
    # FULL SYNC — Fetch all products from a store
    # =========================================================================

    async def sync_all_products(self, store: Store) -> int:
        """
        Full product sync for a store. Fetches all products via paginated
        Shopify REST API and indexes them into ProductIntelligence.

        Args:
            store: Store model with access_token and shopify_domain

        Returns:
            Number of products indexed
        """
        logger.info(f"Starting full sync for {store.shopify_domain}...")

        all_products = await self._fetch_all_products(
            shop=store.shopify_domain,
            access_token=store.access_token,
        )

        if not all_products:
            logger.warning(f"No products found for {store.shopify_domain}")
            return 0

        # Convert Shopify format → CatalogProduct
        catalog_products = []
        for shopify_product in all_products:
            try:
                catalog_product = self._convert_shopify_product(shopify_product, store.shopify_domain)
                if catalog_product:
                    catalog_products.append(catalog_product)
            except Exception as e:
                logger.error(
                    f"Failed to convert product {shopify_product.get('id')}: {e}",
                    exc_info=True,
                )

        logger.info(
            f"Converted {len(catalog_products)}/{len(all_products)} products "
            f"for {store.shopify_domain}"
        )

        # Index into ProductIntelligence
        indexed_count = 0
        try:
            # Import here to avoid circular dependency
            # ProductIntelligence is initialized in main.py lifespan
            from app.services.product_intelligence import ProductIntelligence

            # We need the global instance from main.py
            import main
            pi = getattr(main, "product_intelligence", None)

            if pi is None:
                logger.error("ProductIntelligence not available — cannot index products")
                return 0

            store_namespace = store.store_id_for_pinecone
            indexed_count = await pi.index_products(catalog_products, store_namespace)

            logger.info(
                f"Indexed {indexed_count} products for {store.shopify_domain} "
                f"(namespace: {store_namespace})"
            )
        except Exception as e:
            logger.error(f"Product indexing failed for {store.shopify_domain}: {e}", exc_info=True)

        # Update store sync metadata
        async with get_db() as db:
            result = await db.execute(
                select(Store).where(Store.shopify_domain == store.shopify_domain)
            )
            db_store = result.scalar_one_or_none()
            if db_store:
                db_store.products_count = indexed_count
                db_store.products_synced_at = datetime.now()

        return indexed_count

    # =========================================================================
    # WEBHOOK HANDLER — Process individual product events
    # =========================================================================

    async def handle_product_webhook(
        self,
        shop_domain: str,
        action: str,
        payload: dict,
    ) -> None:
        """
        Handle a single product webhook event.

        Args:
            shop_domain: The store's myshopify.com domain
            action: "upsert" or "delete"
            payload: Shopify webhook payload (product data)
        """
        product_id = str(payload.get("id", ""))
        if not product_id:
            logger.warning("Webhook payload missing product ID")
            return

        # Look up store
        async with get_db() as db:
            result = await db.execute(
                select(Store).where(
                    Store.shopify_domain == shop_domain,
                    Store.is_active == True,
                )
            )
            store = result.scalar_one_or_none()

        if not store:
            logger.warning(f"Webhook for unknown/inactive store: {shop_domain}")
            return

        store_namespace = store.store_id_for_pinecone

        # Get ProductIntelligence instance
        import main
        pi = getattr(main, "product_intelligence", None)
        if pi is None:
            logger.error("ProductIntelligence not available — cannot process webhook")
            return

        if action == "delete":
            await pi.delete_product(f"shopify-{product_id}", store_namespace)
            logger.info(f"Deleted product {product_id} from {shop_domain}")

            # Update count
            async with get_db() as db:
                result = await db.execute(
                    select(Store).where(Store.shopify_domain == shop_domain)
                )
                db_store = result.scalar_one_or_none()
                if db_store and db_store.products_count > 0:
                    db_store.products_count -= 1

        elif action == "upsert":
            catalog_product = self._convert_shopify_product(payload, shop_domain)
            if catalog_product:
                await pi.index_products([catalog_product], store_namespace)
                logger.info(f"Upserted product {product_id} for {shop_domain}")

    # =========================================================================
    # REGISTER WEBHOOKS — Set up Shopify to notify us
    # =========================================================================

    async def register_webhooks(self, store: Store) -> bool:
        """
        Register required webhooks with Shopify for the given store.

        Registers:
        - products/create, products/update, products/delete
        - app/uninstalled
        """
        settings = get_settings()
        webhook_url = f"{settings.app_url}/shopify/webhooks"

        topics = [
            "products/create",
            "products/update",
            "products/delete",
            "app/uninstalled",
        ]

        headers = {
            "X-Shopify-Access-Token": store.access_token,
            "Content-Type": "application/json",
        }

        registered = 0
        async with httpx.AsyncClient(timeout=10.0) as client:
            for topic in topics:
                url = (
                    f"https://{store.shopify_domain}/admin/api/"
                    f"{self.api_version}/webhooks.json"
                )
                payload = {
                    "webhook": {
                        "topic": topic,
                        "address": webhook_url,
                        "format": "json",
                    }
                }

                try:
                    resp = await client.post(url, json=payload, headers=headers)
                    if resp.status_code in (201, 200):
                        registered += 1
                        logger.info(f"Registered webhook: {topic} for {store.shopify_domain}")
                    elif resp.status_code == 422:
                        # Already registered — that's fine
                        logger.info(f"Webhook already exists: {topic} for {store.shopify_domain}")
                        registered += 1
                    else:
                        logger.error(
                            f"Failed to register webhook {topic}: "
                            f"{resp.status_code} {resp.text}"
                        )
                except Exception as e:
                    logger.error(f"Webhook registration error for {topic}: {e}")

                # Respect Shopify rate limits
                await asyncio.sleep(0.5)

        # Update store
        if registered == len(topics):
            async with get_db() as db:
                result = await db.execute(
                    select(Store).where(Store.shopify_domain == store.shopify_domain)
                )
                db_store = result.scalar_one_or_none()
                if db_store:
                    db_store.webhook_registered = True

        logger.info(f"Registered {registered}/{len(topics)} webhooks for {store.shopify_domain}")
        return registered == len(topics)

    # =========================================================================
    # SHOPIFY REST API — Paginated product fetch
    # =========================================================================

    async def _fetch_all_products(
        self,
        shop: str,
        access_token: str,
    ) -> list[dict]:
        """
        Fetch all products from a Shopify store using cursor-based pagination.

        Shopify returns max 250 products per page with a Link header for the next page.
        """
        all_products = []
        url = (
            f"https://{shop}/admin/api/{self.api_version}/products.json"
            f"?limit=250&status=active"
        )
        headers = {"X-Shopify-Access-Token": access_token}

        async with httpx.AsyncClient(timeout=30.0) as client:
            page = 0
            while url:
                page += 1
                logger.info(f"Fetching products page {page} from {shop}...")

                try:
                    resp = await client.get(url, headers=headers)
                    resp.raise_for_status()
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 429:
                        # Rate limited — wait and retry
                        retry_after = float(e.response.headers.get("Retry-After", "2"))
                        logger.warning(f"Rate limited by Shopify — waiting {retry_after}s")
                        await asyncio.sleep(retry_after)
                        continue
                    logger.error(f"Shopify API error on page {page}: {e}")
                    break
                except Exception as e:
                    logger.error(f"Failed to fetch products page {page}: {e}")
                    break

                data = resp.json()
                products = data.get("products", [])
                all_products.extend(products)

                logger.info(f"Page {page}: {len(products)} products (total: {len(all_products)})")

                # Check for next page via Link header
                url = self._get_next_page_url(resp.headers.get("Link", ""))

                # Respect rate limits
                await asyncio.sleep(0.5)

        logger.info(f"Fetched {len(all_products)} total products from {shop}")
        return all_products

    @staticmethod
    def _get_next_page_url(link_header: str) -> Optional[str]:
        """
        Parse Shopify's Link header for cursor-based pagination.

        Format: <https://store.myshopify.com/admin/api/.../products.json?page_info=xxx>; rel="next"
        """
        if not link_header:
            return None

        # Find the "next" link
        matches = re.findall(r'<([^>]+)>;\s*rel="next"', link_header)
        return matches[0] if matches else None

    # =========================================================================
    # PRODUCT CONVERSION — Shopify format → CatalogProduct
    # =========================================================================

    def _convert_shopify_product(self, shopify_product: dict, shop_domain: str = "") -> Optional[CatalogProduct]:
        """
        Convert a Shopify product API response into a CatalogProduct.

        Shopify products have variants, each with its own price/inventory.
        We flatten this: take the first variant's price as the display price,
        and sum inventory across all variants.
        """
        product_id = str(shopify_product.get("id", ""))
        title = shopify_product.get("title", "").strip()

        if not product_id or not title:
            return None

        # --- Price: use first variant's price ---
        variants = shopify_product.get("variants", [])
        price = 0.0
        total_inventory = 0
        sizes = []

        for variant in variants:
            if price == 0:
                try:
                    price = float(variant.get("price", 0))
                except (ValueError, TypeError):
                    pass

            # Sum inventory across variants
            inv = variant.get("inventory_quantity", 0)
            if isinstance(inv, int) and inv > 0:
                total_inventory += inv

            # Collect sizes from variant options
            for option_name in ["option1", "option2", "option3"]:
                opt_val = variant.get(option_name)
                if opt_val and opt_val.upper() in [
                    "XS", "S", "M", "L", "XL", "XXL", "XXXL",
                    "2", "4", "6", "8", "10", "12", "14",
                ] + [str(i) for i in range(5, 16)]:
                    if opt_val not in sizes:
                        sizes.append(opt_val)

        # --- Category: use product_type or first tag ---
        # Normalize to singular form to match entity extractor (e.g. "boots" → "boot")
        category = shopify_product.get("product_type", "").strip()
        if not category:
            tags = shopify_product.get("tags", "")
            if isinstance(tags, str) and tags:
                category = tags.split(",")[0].strip()
        # Normalize plural → singular to match entity extractor
        if category:
            cat_lower = category.lower()
            if cat_lower.endswith("sses"):        # e.g. "dresses" → "dress"
                category = category[:-2]
            elif cat_lower.endswith("ies"):        # e.g. "accessories" → "accessory"
                category = category[:-3] + "y"
            elif cat_lower.endswith("s") and not cat_lower.endswith("ss"):
                category = category[:-1]           # e.g. "boots" → "boot"

        # --- Tags ---
        tags_raw = shopify_product.get("tags", "")
        if isinstance(tags_raw, str):
            tags = [t.strip().lower() for t in tags_raw.split(",") if t.strip()]
        elif isinstance(tags_raw, list):
            tags = [str(t).strip().lower() for t in tags_raw]
        else:
            tags = []

        # --- Colors: extract from variant options ---
        colors = set()
        color_keywords = {
            "red", "blue", "green", "black", "white", "pink", "yellow",
            "orange", "purple", "grey", "gray", "brown", "navy", "beige",
            "cream", "gold", "silver", "tan", "khaki", "olive",
        }
        for variant in variants:
            for option_name in ["option1", "option2", "option3"]:
                opt_val = (variant.get(option_name) or "").lower().strip()
                if opt_val in color_keywords:
                    colors.add(opt_val)

        # --- Image ---
        images = shopify_product.get("images") or []
        image_obj = shopify_product.get("image") or {}
        image_url = images[0].get("src") if images else image_obj.get("src")

        # --- URL ---
        handle = shopify_product.get("handle", "")

        # --- Materials: try to extract from description or tags ---
        description = shopify_product.get("body_html", "") or ""
        # Strip HTML tags for a clean description
        clean_description = re.sub(r"<[^>]+>", " ", description).strip()
        clean_description = re.sub(r"\s+", " ", clean_description)
        # Truncate long descriptions
        if len(clean_description) > 500:
            clean_description = clean_description[:497] + "..."

        materials = []
        material_keywords = [
            "leather", "cotton", "wool", "silk", "polyester", "denim",
            "suede", "linen", "velvet", "satin", "bamboo", "cashmere", "nylon",
        ]
        desc_lower = clean_description.lower()
        for mat in material_keywords:
            if mat in desc_lower or mat in tags:
                materials.append(mat)

        return CatalogProduct(
            id=f"shopify-{product_id}",
            title=title,
            price=price,
            category=category.lower(),
            description=clean_description,
            tags=tags,
            colors=list(colors),
            sizes=sizes,
            materials=materials,
            image_url=image_url,
            url=f"https://{shop_domain}/products/{handle}" if (handle and shop_domain) else None,
            inventory=total_inventory if total_inventory > 0 else 99,
            sales_velocity=0.5,  # Default — will be computed from analytics later
        )


# ============================================================================
# MODULE-LEVEL CONVENIENCE FUNCTION
# ============================================================================

async def sync_store_products(shop_domain: str) -> int:
    """
    Convenience function to sync products for a store by domain.
    Called from the OAuth callback after install.
    """
    async with get_db() as db:
        result = await db.execute(
            select(Store).where(
                Store.shopify_domain == shop_domain,
                Store.is_active == True,
            )
        )
        store = result.scalar_one_or_none()

    if not store:
        logger.error(f"Cannot sync — store not found: {shop_domain}")
        return 0

    sync_service = ShopifySyncService()

    # Sync products
    count = await sync_service.sync_all_products(store)

    # Register webhooks for future updates
    await sync_service.register_webhooks(store)

    return count
