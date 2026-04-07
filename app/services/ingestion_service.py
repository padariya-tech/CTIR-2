"""
CTIR — Ingestion Service (v2)
Orchestrates the full pipeline using repositories and the feed registry.

ThreatFox connector
    → Parser / Validator
        → Deduplication Engine
            → MySQL via IocRepository
                → IngestionJob metrics via JobRepository
"""

import time
from typing import Literal

from sqlalchemy import select

from app.core.logging import get_logger
from app.core.metrics import MetricsCollector, RunMetrics
from app.core.exceptions import (
    FeedConnectionError,
    IngestionAlreadyRunningError,
)
from app.db.database import get_db_context
from app.db.ioc_repository import IocRepository
from app.db.job_repository import IngestionJobRepository
from app.models.models import Feed
from app.schemas.schemas import IngestionJobResponse
from app.services.feed_registry import get_connector
from app.services.parsers.parser import parse_and_validate
from app.services.deduplication.engine import DeduplicationEngine

logger = get_logger(__name__)
metrics = MetricsCollector()

FEED_NAME = "ThreatFox"

# Guard against concurrent runs
_is_running: bool = False


async def _resolve_feed_id(session, feed_name: str) -> int:
    result = await session.execute(select(Feed.id).where(Feed.name == feed_name))
    feed_id = result.scalar_one_or_none()
    if feed_id is None:
        raise RuntimeError(f"Feed '{feed_name}' not in DB. Check migrations/init.sql.")
    return feed_id


async def run_ingestion(
    triggered_by: Literal["scheduler", "manual"] = "scheduler",
    feed_name: str = FEED_NAME,
) -> IngestionJobResponse:
    """
    Execute one complete ingestion cycle:
      1. Fetch raw records from feed
      2. Parse + validate against CTIR schema
      3. Deduplicate and upsert to MySQL
      4. Record job metrics + parse errors
    """
    global _is_running

    if _is_running and triggered_by == "manual":
        raise IngestionAlreadyRunningError()

    _is_running = True
    t_wall = time.monotonic()

    # ── Create job record ─────────────────────────────────────────────────────
    async with get_db_context() as session: # Get a DB session for job record creation
        feed_id = await _resolve_feed_id(session, feed_name) # Look up feed_id from DB using feed_name
        job_repo = IngestionJobRepository(session) # Create a repository instance for managing ingestion jobs
        job = await job_repo.create(feed_id=feed_id, triggered_by=triggered_by)
        job_id = job.id

    logger.info("ingestion_started", job_id=job_id, feed=feed_name, trigger=triggered_by)
    run_metrics = RunMetrics(feed_name=feed_name)

    try:
        from app.core.config import get_settings
        settings = get_settings()

        # ── Step 1: Fetch ─────────────────────────────────────────────────────
        connector = get_connector(feed_name)  # Resolve the appropriate feed connector from the registry based on feed_name
        try:
            async with connector as conn: #
                raw_records, fetch_metrics = await conn.fetch_recent(
                    days=settings.THREATFOX_QUERY_DAYS
                )
                normalize_fn = conn.normalize_record
        except Exception as exc:
            raise FeedConnectionError(str(exc)) from exc

        run_metrics.records_fetched = fetch_metrics["records_fetched"]
        logger.info("step_fetch_done", job_id=job_id, **fetch_metrics)

        # ── Step 2: Parse & Validate ──────────────────────────────────────────
        parse_result = parse_and_validate(raw_records, normalize_fn)
        run_metrics.records_valid = len(parse_result.valid)
        run_metrics.records_invalid = len(parse_result.invalid)
        logger.info(
            "step_parse_done",
            job_id=job_id,
            valid=len(parse_result.valid),
            invalid=len(parse_result.invalid),
        )

        # ── Step 3: Dedup + Store ─────────────────────────────────────────────
        async with get_db_context() as session:
            engine = DeduplicationEngine(session, feed_id)
            dedup_counts = await engine.bulk_upsert(parse_result.valid)

            job_repo = IngestionJobRepository(session)
            await job_repo.bulk_add_parse_errors(job_id, parse_result.errors)

        run_metrics.records_new = dedup_counts.get("new", 0)
        run_metrics.records_updated = dedup_counts.get("updated", 0)
        run_metrics.records_dupes = dedup_counts.get("duplicate", 0)

        logger.info("step_dedup_done", job_id=job_id, **dedup_counts)

        # ── Step 4: Finalise job ──────────────────────────────────────────────
        latency_ms = int((time.monotonic() - t_wall) * 1000)
        run_metrics.latency_ms = latency_ms
        status = "success" if not parse_result.errors else "partial"

        async with get_db_context() as session:
            job_repo = IngestionJobRepository(session)
            job = await job_repo.get_by_id(job_id)
            await job_repo.complete(
                job,
                status=status,
                records_fetched=run_metrics.records_fetched,
                records_parsed=len(raw_records),
                records_valid=run_metrics.records_valid,
                records_invalid=run_metrics.records_invalid,
                records_new=run_metrics.records_new,
                records_updated=run_metrics.records_updated,
                records_dupes=run_metrics.records_dupes,
                latency_ms=latency_ms,
            )

        metrics.record_run(run_metrics)
        logger.info("ingestion_complete", job_id=job_id, status=status, latency_ms=latency_ms)

    except Exception as exc:
        run_metrics.success = False
        latency_ms = int((time.monotonic() - t_wall) * 1000)
        run_metrics.latency_ms = latency_ms
        logger.error("ingestion_failed", job_id=job_id, error=str(exc), exc_info=True)

        async with get_db_context() as session:
            job_repo = IngestionJobRepository(session)
            job = await job_repo.get_by_id(job_id)
            await job_repo.fail(job, error=str(exc), latency_ms=latency_ms)

        metrics.record_run(run_metrics)
        raise

    finally:
        _is_running = False

    async with get_db_context() as session:
        job_repo = IngestionJobRepository(session)
        final_job = await job_repo.get_by_id(job_id)
        return IngestionJobResponse.model_validate(final_job)