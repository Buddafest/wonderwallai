"""
================================================================================
Jerry The Customer Service Bot — Shopify GraphQL Client
================================================================================
File:     app/services/shopify_graphql.py
Version:  1.0.0
Session:  7 (February 2026)

PURPOSE
-------
Async GraphQL client for Shopify Admin API. Used for order lookups, returns,
refunds, and other operations that benefit from GraphQL's flexibility over REST.

USAGE
-----
    from app.services.shopify_graphql import ShopifyGraphQLClient

    client = ShopifyGraphQLClient(shop_domain, access_token)
    order = await client.get_order_by_name("#1001")
================================================================================
"""

import logging
from dataclasses import dataclass
from typing import Any, Optional

import httpx

from app.core.config import get_settings

logger = logging.getLogger("sunsetbot.shopify_graphql")

settings = get_settings()


@dataclass
class GraphQLResponse:
    """Parsed GraphQL response."""
    data: Optional[dict] = None
    errors: Optional[list] = None

    @property
    def ok(self) -> bool:
        return self.errors is None and self.data is not None


class ShopifyGraphQLClient:
    """
    Async Shopify GraphQL Admin API client.

    Each instance is scoped to a single store (shop_domain + access_token).
    """

    def __init__(self, shop_domain: str, access_token: str):
        self.shop_domain = shop_domain
        self.access_token = access_token
        self.api_version = settings.shopify_api_version
        self.endpoint = f"https://{shop_domain}/admin/api/{self.api_version}/graphql.json"

    async def execute(self, query: str, variables: Optional[dict] = None) -> GraphQLResponse:
        """Execute a GraphQL query/mutation against the Shopify Admin API."""
        headers = {
            "X-Shopify-Access-Token": self.access_token,
            "Content-Type": "application/json",
        }
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(self.endpoint, json=payload, headers=headers)
                resp.raise_for_status()
                body = resp.json()

                if "errors" in body:
                    logger.error(f"GraphQL errors for {self.shop_domain}: {body['errors']}")
                    return GraphQLResponse(errors=body["errors"])

                return GraphQLResponse(data=body.get("data"))

        except httpx.HTTPStatusError as e:
            logger.error(f"GraphQL HTTP error for {self.shop_domain}: {e.response.status_code}")
            return GraphQLResponse(errors=[{"message": f"HTTP {e.response.status_code}"}])
        except Exception as e:
            logger.error(f"GraphQL request failed for {self.shop_domain}: {e}", exc_info=True)
            return GraphQLResponse(errors=[{"message": str(e)}])

    # ─────────────────────────────────────────────────────────────
    # ORDER QUERIES
    # ─────────────────────────────────────────────────────────────

    async def get_order_by_name(self, order_name: str) -> GraphQLResponse:
        """
        Look up an order by its display name (e.g., "#1001").

        Returns order details including line items, fulfillments, and financial status.
        """
        # Ensure the order name starts with #
        if not order_name.startswith("#"):
            order_name = f"#{order_name}"

        query = """
        query getOrderByName($query: String!) {
            orders(first: 1, query: $query) {
                nodes {
                    id
                    name
                    email
                    displayFinancialStatus
                    displayFulfillmentStatus
                    totalPriceSet { shopMoney { amount currencyCode } }
                    createdAt
                    cancelledAt
                    lineItems(first: 50) {
                        nodes {
                            id
                            name
                            sku
                            quantity
                            originalTotalSet { shopMoney { amount currencyCode } }
                        }
                    }
                    fulfillments(first: 10) {
                        nodes {
                            id
                            status
                            trackingInfo(first: 5) {
                                number
                                url
                                company
                            }
                            fulfillmentLineItems(first: 50) {
                                nodes {
                                    id
                                    quantity
                                    lineItem { id sku name }
                                }
                            }
                        }
                    }
                }
            }
        }
        """
        return await self.execute(query, {"query": f"name:{order_name}"})

    async def get_fulfillment_line_items(self, order_gid: str) -> GraphQLResponse:
        """
        Extract fulfillmentLineItemIds for an order — required for returnCreate.

        The agent matches the customer's requested item (by SKU or name) to the
        correct fulfillmentLineItems.nodes.id.
        """
        query = """
        query getFulfillmentLineItems($orderId: ID!) {
            order(id: $orderId) {
                id
                fulfillments(first: 10) {
                    nodes {
                        id
                        status
                        fulfillmentLineItems(first: 50) {
                            nodes {
                                id
                                quantity
                                lineItem { id sku name }
                            }
                        }
                    }
                }
            }
        }
        """
        return await self.execute(query, {"orderId": order_gid})

    async def get_order_transactions(self, order_gid: str) -> GraphQLResponse:
        """
        Extract the original transaction parentId — required for refundCreate.

        The agent finds the transaction where kind=CAPTURE or SALE and status=SUCCESS,
        then uses that ID as parentId in the refund mutation.
        """
        query = """
        query getOrderTransactions($orderId: ID!) {
            order(id: $orderId) {
                id
                transactions(first: 10) {
                    nodes {
                        id
                        kind
                        status
                        gateway
                        amountSet {
                            shopMoney { amount currencyCode }
                        }
                    }
                }
            }
        }
        """
        return await self.execute(query, {"orderId": order_gid})

    # ─────────────────────────────────────────────────────────────
    # RETURN / REFUND MUTATIONS
    # ─────────────────────────────────────────────────────────────

    async def create_return(
        self, order_gid: str, return_line_items: list[dict]
    ) -> GraphQLResponse:
        """
        Create a return request in Shopify.

        return_line_items should be a list of dicts:
            [{"fulfillmentLineItemId": "gid://...", "quantity": 1, "returnReason": "WRONG_ITEM"}]
        """
        mutation = """
        mutation returnCreate($input: ReturnInput!) {
            returnCreate(input: $input) {
                return {
                    id
                    status
                }
                userErrors {
                    field
                    message
                }
            }
        }
        """
        variables = {
            "input": {
                "orderId": order_gid,
                "returnLineItems": return_line_items,
            }
        }
        return await self.execute(mutation, variables)

    async def create_refund(
        self,
        order_gid: str,
        refund_line_items: list[dict],
        parent_transaction_id: str,
        note: str = "Refund processed by Jerry The Customer Service Bot.",
    ) -> GraphQLResponse:
        """
        Create a refund in Shopify.

        refund_line_items: [{"lineItemId": "gid://...", "quantity": 1}]
        parent_transaction_id: The ID of the original CAPTURE/SALE transaction.
        """
        mutation = """
        mutation refundCreate($input: RefundInput!) {
            refundCreate(input: $input) {
                refund {
                    id
                }
                userErrors {
                    field
                    message
                }
            }
        }
        """
        variables = {
            "input": {
                "orderId": order_gid,
                "refundLineItems": refund_line_items,
                "transactions": [
                    {
                        "parentId": parent_transaction_id,
                        "kind": "REFUND",
                        "gateway": "shopify_payments",
                    }
                ],
                "note": note,
            }
        }
        return await self.execute(mutation, variables)
