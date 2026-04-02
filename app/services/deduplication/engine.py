"""
Deduplication Engine
─────────────────────
• Canonical key  = SHA-256( ioc_type + ':' + normalised_value )
• On duplicate:
    – keep highest confidence
    – keep most severe severity
    – update last_seen_at
    – increment source_count
    – append to merged_sources
• Idempotent: re-running the same feed produces zero net-new rows.
"""

import hashlib
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.models.models import Ioc, IocType
from app.schemas.schemas import NormalizedIoc

logger = get_logger(__name__)

_SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def compute_ioc_hash(ioc_type: str, ioc_value: str) -> str:
    """Deterministic dedup key."""
    canonical = f"{ioc_type}:{ioc_value.strip().lower()}"
    return hashlib.sha256(canonical.encode()).hexdigest()


def _merge_severity(existing: str, incoming: str) -> str:
    return (
        existing
        if _SEVERITY_RANK.get(existing, 0) >= _SEVERITY_RANK.get(incoming, 0)
        else incoming
    )


class DeduplicationEngine:
    def __init__(self, session: AsyncSession, feed_id: int) -> None:
        self._session = session
        self._feed_id = feed_id

    async def _get_type_id(self, type_name: str) -> int:
        result = await self._session.execute(
            select(IocType.id).where(IocType.name == type_name)
        )
        row = result.scalar_one_or_none()
        if row is None:
            # Fall back to 'other'
            result = await self._session.execute(
                select(IocType.id).where(IocType.name == "other")
            )
            row = result.scalar_one()
        return row

    async def upsert(
        self, ioc: NormalizedIoc
    ) -> tuple[str, Ioc]:
        """
        Insert or update an IOC.
        Returns ("new" | "updated" | "duplicate", orm_instance).
        """
        ioc_hash = compute_ioc_hash(ioc.ioc_type, ioc.ioc_value)

        # Lookup existing row
        result = await self._session.execute(
            select(Ioc).where(Ioc.ioc_hash == ioc_hash)
        )
        existing: Ioc | None = result.scalar_one_or_none()

        if existing is None:
            # ── New IOC ───────────────────────────────────────────────
            type_id = await self._get_type_id(ioc.ioc_type)
            new_ioc = Ioc(
                ioc_value=ioc.ioc_value,
                ioc_type_id=type_id,
                ioc_hash=ioc_hash,
                malware_family=ioc.malware_family,
                threat_type=ioc.threat_type,
                confidence=ioc.confidence,
                severity=ioc.severity,
                tags=ioc.tags or [],
                primary_feed_id=self._feed_id,
                source_ioc_id=ioc.source_ioc_id,
                source_count=1,
                merged_sources=[
                    {
                        "feed_id": self._feed_id,
                        "source_ioc_id": ioc.source_ioc_id,
                        "first_seen": ioc.first_seen_at.isoformat(),
                    }
                ],
                first_seen_at=ioc.first_seen_at,
                last_seen_at=ioc.last_seen_at,
                expires_at=ioc.expires_at,
                is_active=True,
            )
            self._session.add(new_ioc)
            return "new", new_ioc

        # ── Duplicate detected ────────────────────────────────────────
        changed = False

        # Conflict resolution: prefer higher confidence
        if ioc.confidence > existing.confidence:
            existing.confidence = ioc.confidence
            changed = True

        # Conflict resolution: prefer more severe rating
        new_severity = _merge_severity(existing.severity, ioc.severity)
        if new_severity != existing.severity:
            existing.severity = new_severity
            changed = True

        # Always refresh last_seen
        if ioc.last_seen_at > existing.last_seen_at:
            existing.last_seen_at = ioc.last_seen_at
            changed = True

        # Merge tags
        existing_tags: list = existing.tags or []
        new_tags = [t for t in (ioc.tags or []) if t not in existing_tags]
        if new_tags:
            existing.tags = existing_tags + new_tags
            changed = True

        # Source attribution
        existing_sources: list = existing.merged_sources or []
        already_attributed = any(
            s.get("source_ioc_id") == ioc.source_ioc_id
            for s in existing_sources
        )
        if not already_attributed and ioc.source_ioc_id:
            existing_sources.append(
                {
                    "feed_id": self._feed_id,
                    "source_ioc_id": ioc.source_ioc_id,
                    "first_seen": ioc.first_seen_at.isoformat(),
                }
            )
            existing.merged_sources = existing_sources
            existing.source_count = len(existing_sources)
            changed = True

        status = "updated" if changed else "duplicate"
        logger.debug("dedup_result", status=status, ioc_hash=ioc_hash[:16])
        return status, existing

    async def bulk_upsert(
        self, iocs: list[NormalizedIoc]
    ) -> dict[str, int]:
        """
        Process a batch of NormalizedIocs.
        Flushes every 500 records to avoid huge transactions.
        Returns counts: {new, updated, duplicate}.
        """
        counts: dict[str, int] = {"new": 0, "updated": 0, "duplicate": 0}
        BATCH = 500

        for i, ioc in enumerate(iocs, 1):
            try:
                status, _ = await self.upsert(ioc)
                counts[status] += 1
            except Exception as exc:
                logger.error(
                    "dedup_upsert_error",
                    ioc_value=ioc.ioc_value,
                    error=str(exc),
                )
                counts.setdefault("error", 0)
                counts["error"] += 1

            if i % BATCH == 0:
                await self._session.flush()
                logger.debug("dedup_flush", processed=i)

        await self._session.flush()
        logger.info("dedup_complete", **counts)
        return counts