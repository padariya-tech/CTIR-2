"""
Background scheduler — runs ingestion on a configurable interval.
"""

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.interval import IntervalTrigger

from app.core.config import get_settings
from app.core.logging import get_logger

logger = get_logger(__name__)
settings = get_settings()

scheduler = AsyncIOScheduler()


async def _scheduled_ingestion() -> None:
    from app.services.ingestion_service import run_ingestion
    try:
        logger.info("scheduler_trigger", source="interval")
        await run_ingestion(triggered_by="scheduler")
    except Exception as exc:
        logger.error("scheduler_ingestion_error", error=str(exc))


def start_scheduler() -> None:
    scheduler.add_job(
        _scheduled_ingestion,
        trigger=IntervalTrigger(minutes=settings.INGESTION_SCHEDULE_MINUTES),
        id="threatfox_ingestion",
        replace_existing=True,
        max_instances=1,
        misfire_grace_time=60,
    )
    scheduler.start()
    logger.info(
        "scheduler_started",
        interval_minutes=settings.INGESTION_SCHEDULE_MINUTES,
    )


def stop_scheduler() -> None:
    if scheduler.running:
        scheduler.shutdown(wait=False)
        logger.info("scheduler_stopped")