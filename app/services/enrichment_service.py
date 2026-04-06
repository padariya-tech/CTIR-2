"""
CTIR — Enrichment Service
On-demand enrichment of an IOC value against ThreatFox.
Returns merged intelligence from the upstream feed without
storing anything — callers decide whether to persist.
"""

from datetime import datetime, timezone
from typing import Optional

from app.core.logging import get_logger
from app.services.connectors.threatfox import ThreatFoxConnector
from app.schemas.schemas import NormalizedIoc

logger = get_logger(__name__)


class EnrichmentResult:
    __slots__ = ("ioc_value", "found", "records", "raw_response")

    def __init__(
        self,
        ioc_value: str,
        found: bool,
        records: list[NormalizedIoc],
        raw_response: list[dict],
    ) -> None:
        self.ioc_value = ioc_value
        self.found = found
        self.records = records
        self.raw_response = raw_response


async def enrich_ioc(ioc_value: str) -> EnrichmentResult:
    """
    Query ThreatFox for a specific IOC value.
    Normalises results into NormalizedIoc objects.
    Does NOT write to the database.
    """
    logger.info("enrichment_requested", ioc_value=ioc_value)

    async with ThreatFoxConnector() as connector:
        try:
            raw_records = await connector.search_ioc(ioc_value)
        except Exception as exc:
            logger.error("enrichment_fetch_failed", ioc_value=ioc_value, error=str(exc))
            raise

    if not raw_records:
        logger.info("enrichment_not_found", ioc_value=ioc_value)
        return EnrichmentResult(
            ioc_value=ioc_value,
            found=False,
            records=[],
            raw_response=[],
        )

    normalized: list[NormalizedIoc] = []
    for raw in raw_records:
        try:
            d = connector.normalize_record(raw)
            if d:
                normalized.append(NormalizedIoc(**d))
        except Exception as exc:
            logger.warning("enrichment_normalize_failed", error=str(exc))

    logger.info(
        "enrichment_complete",
        ioc_value=ioc_value,
        raw_count=len(raw_records),
        normalized_count=len(normalized),
    )
    return EnrichmentResult(
        ioc_value=ioc_value,
        found=bool(normalized),
        records=normalized,
        raw_response=raw_records,
    )