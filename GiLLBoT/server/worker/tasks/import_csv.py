"""
GiLLBoT — CSV Import Task
Worker task for bulk importing leads from a CSV file.
Runs in the background after a user uploads a CSV.
"""

from __future__ import annotations

import logging
import uuid

logger = logging.getLogger("gillbot.import_csv")


async def import_csv_task(
    ctx: dict,
    user_id: str,
    file_content_b64: str,
    lead_list_id: str,
) -> dict:
    """
    ARQ task: parse a CSV and bulk-insert leads for a user.

    Args:
        ctx: ARQ context dict.
        user_id: UUID string of the owning user.
        file_content_b64: Base64-encoded CSV file content.
        lead_list_id: UUID string of the LeadList to add leads to.

    Returns:
        Result dict with counts of imported and skipped leads.
    """
    import base64

    logger.info(f"import_csv_task: user_id={user_id} list={lead_list_id}")

    file_bytes = base64.b64decode(file_content_b64)

    # TODO: implement full CSV import
    # 1. Parse CSV via CSVImportService
    # 2. Deduplicate against existing leads (by email)
    # 3. Bulk insert Lead rows
    # 4. Create LeadListMember rows
    # 5. Return import summary

    return {
        "status": "stub",
        "user_id": user_id,
        "lead_list_id": lead_list_id,
        "imported": 0,
        "skipped": 0,
        "message": "import_csv_task not yet implemented",
    }
