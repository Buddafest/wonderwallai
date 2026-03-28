"""
GiLLBoT — CSV Import Service
Parses and imports lead data from uploaded CSV files.
"""

from __future__ import annotations

import csv
import io
import logging
from typing import Optional
import uuid

logger = logging.getLogger("gillbot.csv_import")

# Expected CSV column names (case-insensitive, flexible mapping)
COLUMN_ALIASES: dict[str, list[str]] = {
    "email": ["email", "email_address", "e-mail"],
    "first_name": ["first_name", "firstname", "first", "fname"],
    "last_name": ["last_name", "lastname", "last", "lname"],
    "company": ["company", "company_name", "organization", "org"],
    "title": ["title", "job_title", "position", "role"],
    "phone": ["phone", "phone_number", "mobile", "tel"],
    "linkedin_url": ["linkedin_url", "linkedin", "linkedin_profile"],
    "website": ["website", "website_url", "url", "domain"],
}


class CSVImportService:
    """Parses CSV files and converts rows into lead dicts for bulk import."""

    def parse_csv(self, file_content: bytes) -> list[dict]:
        """
        Parse CSV bytes into a list of lead dicts.

        Args:
            file_content: Raw CSV file bytes.

        Returns:
            List of lead dicts with normalized field names.
        """
        # TODO: implement full CSV parsing with column detection and validation
        text = file_content.decode("utf-8-sig")  # handle BOM
        reader = csv.DictReader(io.StringIO(text))
        leads = []

        for row in reader:
            lead = self._map_row(row)
            if lead.get("email") or lead.get("linkedin_url"):
                leads.append(lead)

        logger.info(f"Parsed {len(leads)} leads from CSV")
        return leads

    def _map_row(self, row: dict) -> dict:
        """Map a CSV row to normalized lead field names."""
        normalized: dict = {}
        lower_row = {k.strip().lower(): v.strip() for k, v in row.items() if v}

        for field, aliases in COLUMN_ALIASES.items():
            for alias in aliases:
                if alias in lower_row:
                    normalized[field] = lower_row[alias]
                    break

        # Preserve unmapped columns as custom_fields
        mapped_keys = {
            alias for aliases in COLUMN_ALIASES.values() for alias in aliases
        }
        custom = {
            k: v for k, v in lower_row.items() if k not in mapped_keys and v
        }
        if custom:
            normalized["custom_fields"] = custom

        return normalized
