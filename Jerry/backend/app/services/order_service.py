"""
================================================================================
Jerry The Customer Service Bot — Order Service
================================================================================
File:     app/services/order_service.py
Version:  1.0.0
Session:  7 (February 2026)

PURPOSE
-------
Handles order lookups (WISMO), returns, and refunds via the Shopify GraphQL
Admin API. Called by the ConversationEngine when the intent is order_tracking
or support (with return/refund sub-intent).

USAGE
-----
    from app.services.order_service import OrderService

    service = OrderService()
    order = await service.lookup_order("shop.myshopify.com", "#1001")
    tracking = await service.get_tracking_info("shop.myshopify.com", order.gid)
================================================================================
"""

import logging
from dataclasses import dataclass, field
from typing import Optional

from sqlalchemy import select

from app.db.engine import get_db
from app.db.models import Store
from app.services.shopify_graphql import ShopifyGraphQLClient

logger = logging.getLogger("sunsetbot.order_service")


# ─────────────────────────────────────────────────────────────
# DATA MODELS
# ─────────────────────────────────────────────────────────────

@dataclass
class LineItem:
    """A single item in an order."""
    gid: str
    name: str
    sku: str
    quantity: int
    total: str
    currency: str


@dataclass
class TrackingInfo:
    """Fulfillment tracking details."""
    number: Optional[str] = None
    url: Optional[str] = None
    company: Optional[str] = None


@dataclass
class FulfillmentInfo:
    """A fulfillment within an order."""
    gid: str
    status: str
    tracking: Optional[TrackingInfo] = None
    line_items: list[dict] = field(default_factory=list)


@dataclass
class OrderInfo:
    """Structured order data returned from Shopify."""
    gid: str
    name: str  # "#1001"
    email: Optional[str]
    financial_status: str
    fulfillment_status: str
    total: str
    currency: str
    created_at: str
    cancelled_at: Optional[str]
    line_items: list[LineItem] = field(default_factory=list)
    fulfillments: list[FulfillmentInfo] = field(default_factory=list)


@dataclass
class ReturnResult:
    """Result of a return request."""
    success: bool
    return_id: Optional[str] = None
    error: Optional[str] = None


@dataclass
class RefundResult:
    """Result of a refund request."""
    success: bool
    refund_id: Optional[str] = None
    error: Optional[str] = None


# ─────────────────────────────────────────────────────────────
# ORDER SERVICE
# ─────────────────────────────────────────────────────────────

class OrderService:
    """
    Handles order-related operations: lookups, tracking, returns, refunds.

    Fetches the store's access token from the database, then uses the
    ShopifyGraphQLClient to query/mutate the Shopify Admin API.
    """

    async def _get_client(self, shop_domain: str) -> Optional[ShopifyGraphQLClient]:
        """Get an authenticated GraphQL client for a store."""
        async with get_db() as db:
            result = await db.execute(
                select(Store).where(
                    Store.shopify_domain == shop_domain,
                    Store.is_active == True,
                )
            )
            store = result.scalar_one_or_none()

        if not store:
            logger.warning(f"Store not found or inactive: {shop_domain}")
            return None

        return ShopifyGraphQLClient(shop_domain, store.access_token)

    # ─────────────────────────── WISMO ───────────────────────────

    async def lookup_order(self, shop_domain: str, order_name: str) -> Optional[OrderInfo]:
        """
        Look up an order by its display name (e.g., "#1001").

        Returns structured OrderInfo or None if not found.
        """
        client = await self._get_client(shop_domain)
        if not client:
            return None

        resp = await client.get_order_by_name(order_name)
        if not resp.ok:
            logger.error(f"Order lookup failed: {resp.errors}")
            return None

        orders = resp.data.get("orders", {}).get("nodes", [])
        if not orders:
            return None

        order = orders[0]
        return self._parse_order(order)

    async def get_tracking_info(self, shop_domain: str, order_name: str) -> Optional[str]:
        """
        Get a human-readable tracking update for an order.

        Returns a formatted string suitable for the LLM to incorporate into its response.
        """
        order = await self.lookup_order(shop_domain, order_name)
        if not order:
            return None

        return self._format_tracking(order)

    # ─────────────────────────── RETURNS ───────────────────────────

    async def initiate_return(
        self,
        shop_domain: str,
        order_name: str,
        item_name: str,
        reason: str = "OTHER",
    ) -> ReturnResult:
        """
        Initiate a return for a specific item in an order.

        Looks up the order, finds the matching fulfillment line item,
        and creates a return via the Shopify GraphQL API.
        """
        client = await self._get_client(shop_domain)
        if not client:
            return ReturnResult(success=False, error="Store not found")

        # 1. Look up the order
        order_resp = await client.get_order_by_name(order_name)
        if not order_resp.ok or not order_resp.data.get("orders", {}).get("nodes"):
            return ReturnResult(success=False, error=f"Order {order_name} not found")

        order = order_resp.data["orders"]["nodes"][0]
        order_gid = order["id"]

        # 2. Get fulfillment line items
        fl_resp = await client.get_fulfillment_line_items(order_gid)
        if not fl_resp.ok:
            return ReturnResult(success=False, error="Could not retrieve fulfillment data")

        # 3. Match the customer's item to a fulfillment line item
        fulfillment_line_item_id = self._match_item_to_fulfillment(
            fl_resp.data, item_name
        )
        if not fulfillment_line_item_id:
            return ReturnResult(
                success=False,
                error=f"Could not find '{item_name}' in the fulfilled items for {order_name}",
            )

        # 4. Create the return
        return_resp = await client.create_return(
            order_gid,
            [{"fulfillmentLineItemId": fulfillment_line_item_id, "quantity": 1, "returnReason": reason}],
        )

        if not return_resp.ok:
            return ReturnResult(success=False, error=str(return_resp.errors))

        return_data = return_resp.data.get("returnCreate", {})
        user_errors = return_data.get("userErrors", [])
        if user_errors:
            return ReturnResult(success=False, error=user_errors[0].get("message", "Unknown error"))

        return_id = return_data.get("return", {}).get("id")
        logger.info(f"Return created for {order_name} / {item_name}: {return_id}")
        return ReturnResult(success=True, return_id=return_id)

    # ─────────────────────────── REFUNDS ───────────────────────────

    async def process_refund(
        self,
        shop_domain: str,
        order_name: str,
        item_name: str,
    ) -> RefundResult:
        """
        Process a refund for a specific item in an order.

        Looks up the order, finds the transaction parent ID, and creates
        a refund via the Shopify GraphQL API.
        """
        client = await self._get_client(shop_domain)
        if not client:
            return RefundResult(success=False, error="Store not found")

        # 1. Look up the order
        order_resp = await client.get_order_by_name(order_name)
        if not order_resp.ok or not order_resp.data.get("orders", {}).get("nodes"):
            return RefundResult(success=False, error=f"Order {order_name} not found")

        order = order_resp.data["orders"]["nodes"][0]
        order_gid = order["id"]

        # 2. Find the line item to refund
        line_item_id = self._match_item_to_line_item(order, item_name)
        if not line_item_id:
            return RefundResult(
                success=False,
                error=f"Could not find '{item_name}' in order {order_name}",
            )

        # 3. Get the parent transaction ID
        tx_resp = await client.get_order_transactions(order_gid)
        if not tx_resp.ok:
            return RefundResult(success=False, error="Could not retrieve transaction data")

        parent_tx_id = self._find_parent_transaction(tx_resp.data)
        if not parent_tx_id:
            return RefundResult(
                success=False,
                error="No successful capture/sale transaction found for this order",
            )

        # 4. Create the refund
        refund_resp = await client.create_refund(
            order_gid,
            [{"lineItemId": line_item_id, "quantity": 1}],
            parent_tx_id,
        )

        if not refund_resp.ok:
            return RefundResult(success=False, error=str(refund_resp.errors))

        refund_data = refund_resp.data.get("refundCreate", {})
        user_errors = refund_data.get("userErrors", [])
        if user_errors:
            return RefundResult(success=False, error=user_errors[0].get("message", "Unknown error"))

        refund_id = refund_data.get("refund", {}).get("id")
        logger.info(f"Refund created for {order_name} / {item_name}: {refund_id}")
        return RefundResult(success=True, refund_id=refund_id)

    # ─────────────────────────── REFUND WEBHOOK PARSER ───────────────────────────

    @staticmethod
    def parse_refund_webhook(payload: dict) -> str:
        """
        Parse the REFUNDS_CREATE webhook payload and generate a customer update.

        Extracts: order_id, transaction status/amount/currency, product titles.
        Returns a formatted string for the customer.
        """
        try:
            order_id = payload.get("order_id")
            transactions = payload.get("transactions", [])
            refund_line_items = payload.get("refund_line_items", [])

            if not transactions:
                return (
                    f"Your refund for order #{order_id} has been initiated, "
                    "but financial details are currently pending."
                )

            primary_transaction = transactions[0]
            status = primary_transaction.get("status")
            amount = primary_transaction.get("amount")
            currency = primary_transaction.get("currency")

            if status != "success":
                return (
                    f"The refund for order #{order_id} is currently marked as '{status}'. "
                    "You will receive another update once the funds successfully clear."
                )

            # Extract refunded product titles
            product_titles = []
            for item in refund_line_items:
                line_item = item.get("line_item")
                if line_item and line_item.get("title"):
                    product_titles.append(line_item["title"])

            items_string = ", ".join(product_titles) if product_titles else "your returned items"

            return (
                f"The refund for {items_string} from order #{order_id} "
                f"has been successfully processed. A total of {amount} {currency} "
                "has been returned to your original payment method."
            )

        except Exception:
            return (
                f"Your refund for order #{payload.get('order_id', 'unknown')} is processing. "
                "Please check your email for the official receipt."
            )

    # ─────────────────────────── HELPERS ───────────────────────────

    def _parse_order(self, order: dict) -> OrderInfo:
        """Parse a raw GraphQL order node into an OrderInfo dataclass."""
        line_items = []
        for item in order.get("lineItems", {}).get("nodes", []):
            money = item.get("originalTotalSet", {}).get("shopMoney", {})
            line_items.append(LineItem(
                gid=item["id"],
                name=item.get("name", ""),
                sku=item.get("sku", ""),
                quantity=item.get("quantity", 0),
                total=money.get("amount", "0"),
                currency=money.get("currencyCode", "USD"),
            ))

        fulfillments = []
        for ful in order.get("fulfillments", {}).get("nodes", []):
            tracking = None
            tracking_infos = ful.get("trackingInfo", [])
            if tracking_infos:
                t = tracking_infos[0]
                tracking = TrackingInfo(
                    number=t.get("number"),
                    url=t.get("url"),
                    company=t.get("company"),
                )

            fl_items = []
            for fli in ful.get("fulfillmentLineItems", {}).get("nodes", []):
                fl_items.append({
                    "id": fli["id"],
                    "quantity": fli.get("quantity", 0),
                    "lineItem": fli.get("lineItem", {}),
                })

            fulfillments.append(FulfillmentInfo(
                gid=ful["id"],
                status=ful.get("status", "UNKNOWN"),
                tracking=tracking,
                line_items=fl_items,
            ))

        money = order.get("totalPriceSet", {}).get("shopMoney", {})
        return OrderInfo(
            gid=order["id"],
            name=order.get("name", ""),
            email=order.get("email"),
            financial_status=order.get("displayFinancialStatus", "UNKNOWN"),
            fulfillment_status=order.get("displayFulfillmentStatus", "UNKNOWN"),
            total=money.get("amount", "0"),
            currency=money.get("currencyCode", "USD"),
            created_at=order.get("createdAt", ""),
            cancelled_at=order.get("cancelledAt"),
            line_items=line_items,
            fulfillments=fulfillments,
        )

    def _format_tracking(self, order: OrderInfo) -> str:
        """Format order + tracking info into a string for the LLM context."""
        parts = [
            f"Order {order.name}:",
            f"  Status: {order.fulfillment_status}",
            f"  Financial: {order.financial_status}",
            f"  Total: {order.total} {order.currency}",
            f"  Items: {', '.join(li.name for li in order.line_items)}",
        ]

        if order.cancelled_at:
            parts.append(f"  CANCELLED at {order.cancelled_at}")

        for ful in order.fulfillments:
            parts.append(f"  Fulfillment: {ful.status}")
            if ful.tracking:
                if ful.tracking.company:
                    parts.append(f"    Carrier: {ful.tracking.company}")
                if ful.tracking.number:
                    parts.append(f"    Tracking #: {ful.tracking.number}")
                if ful.tracking.url:
                    parts.append(f"    Track here: {ful.tracking.url}")

        if not order.fulfillments:
            parts.append("  No fulfillments yet — order may still be processing.")

        return "\n".join(parts)

    def _match_item_to_fulfillment(self, data: dict, item_name: str) -> Optional[str]:
        """Match a product name to a fulfillmentLineItemId."""
        item_lower = item_name.lower()
        order = data.get("order", {})

        for ful in order.get("fulfillments", {}).get("nodes", []):
            for fli in ful.get("fulfillmentLineItems", {}).get("nodes", []):
                li = fli.get("lineItem", {})
                name = (li.get("name") or "").lower()
                sku = (li.get("sku") or "").lower()
                if item_lower in name or item_lower in sku:
                    return fli["id"]

        return None

    def _match_item_to_line_item(self, order: dict, item_name: str) -> Optional[str]:
        """Match a product name to a regular lineItem ID (for refunds)."""
        item_lower = item_name.lower()

        for li in order.get("lineItems", {}).get("nodes", []):
            name = (li.get("name") or "").lower()
            sku = (li.get("sku") or "").lower()
            if item_lower in name or item_lower in sku:
                return li["id"]

        return None

    def _find_parent_transaction(self, data: dict) -> Optional[str]:
        """Find the original CAPTURE/SALE transaction ID for a refund."""
        order = data.get("order", {})

        for tx in order.get("transactions", {}).get("nodes", []):
            kind = (tx.get("kind") or "").upper()
            status = (tx.get("status") or "").upper()
            if kind in ("CAPTURE", "SALE") and status == "SUCCESS":
                return tx["id"]

        return None
