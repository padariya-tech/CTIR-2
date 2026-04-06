"""
CTIR — Ingestion Job Repository
Centralises all DB operations for ingestion_jobs and parse_errors.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import IngestionJobNotFoundError
from app.core.logging import get_logger
from app.models.models import IngestionJob, ParseError

logger = get_logger(__name__)


class IngestionJobRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._db = session

    # ── IngestionJob CRUD ─────────────────────────────────────────────────────

    async def create(self, feed_id: int, triggered_by: str) -> IngestionJob:
        job = IngestionJob(
            feed_id=feed_id,
            triggered_by=triggered_by,
            status="running",
        )
        self._db.add(job)
        await self._db.flush()
        logger.info("ingestion_job_created", job_id=job.id, triggered_by=triggered_by)
        return job

    async def get_by_id(self, job_id: int) -> IngestionJob:
        result = await self._db.execute(
            select(IngestionJob).where(IngestionJob.id == job_id)
        )
        row = result.scalar_one_or_none()
        if row is None:
            raise IngestionJobNotFoundError(f"Job id={job_id} not found")
        return row

    async def list_recent(self, limit: int = 20) -> list[IngestionJob]:
        result = await self._db.execute(
            select(IngestionJob)
            .order_by(IngestionJob.started_at.desc())
            .limit(limit)
        )
        return list(result.scalars().all())

    async def complete(
        self,
        job: IngestionJob,
        *,
        status: str,
        records_fetched: int = 0,
        records_parsed: int = 0,
        records_valid: int = 0,
        records_invalid: int = 0,
        records_new: int = 0,
        records_updated: int = 0,
        records_dupes: int = 0,
        latency_ms: int = 0,
        error_message: Optional[str] = None,
    ) -> IngestionJob:
        job.status = status
        job.records_fetched = records_fetched
        job.records_parsed = records_parsed
        job.records_valid = records_valid
        job.records_invalid = records_invalid
        job.records_new = records_new
        job.records_updated = records_updated
        job.records_dupes = records_dupes
        job.finished_at = datetime.now(timezone.utc)
        job.latency_ms = latency_ms
        job.error_message = error_message
        await self._db.flush()
        logger.info(
            "ingestion_job_completed",
            job_id=job.id,
            status=status,
            latency_ms=latency_ms,
        )
        return job

    async def fail(self, job: IngestionJob, error: str, latency_ms: int = 0) -> IngestionJob:
        return await self.complete(
            job,
            status="failed",
            error_message=error[:2000],
            latency_ms=latency_ms,
        )

    # ── ParseError helpers ────────────────────────────────────────────────────

    async def bulk_add_parse_errors(
        self, job_id: int, errors: list[dict]
    ) -> int:
        if not errors:
            return 0
        objs = [
            ParseError(
                job_id=job_id,
                raw_data=e.get("raw"),
                error_type=e.get("error_type"),
                error_msg=str(e.get("error_msg", ""))[:2000],
            )
            for e in errors
        ]
        self._db.add_all(objs)
        await self._db.flush()
        return len(objs)

    async def list_parse_errors(self, job_id: int, limit: int = 100) -> list[ParseError]:
        result = await self._db.execute(
            select(ParseError)
            .where(ParseError.job_id == job_id)
            .order_by(ParseError.created_at)
            .limit(limit)
        )
        return list(result.scalars().all())

    # ── Aggregates ────────────────────────────────────────────────────────────

    async def total_count(self) -> int:
        return (
            await self._db.execute(select(func.count(IngestionJob.id)))
        ).scalar_one()

    async def latest(self) -> Optional[IngestionJob]:
        result = await self._db.execute(
            select(IngestionJob).order_by(IngestionJob.started_at.desc()).limit(1)
        )
        return result.scalar_one_or_none()  