from fastapi import APIRouter, Depends
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.metrics import MetricsCollector
from app.db.database import get_db, check_db_connection
from app.db.ioc_repository import IocRepository
from app.db.job_repository import IngestionJobRepository
from app.schemas.schemas import HealthResponse, StatsResponse, IngestionJobResponse
from app.core.config import get_settings

router = APIRouter(tags=["System"])
settings = get_settings()
metrics = MetricsCollector()


@router.get("/health", response_model=HealthResponse)
async def health():
    db_ok = await check_db_connection()
    return HealthResponse(
        status="ok" if db_ok else "degraded",
        database=db_ok,
        version=settings.API_VERSION,
    )


@router.get("/stats", response_model=StatsResponse)
async def stats(db: AsyncSession = Depends(get_db)):
    ioc_repo = IocRepository(db)
    job_repo = IngestionJobRepository(db)

    total_iocs = await ioc_repo.total_count()
    active_iocs = await ioc_repo.total_count(is_active=True)
    iocs_by_type = await ioc_repo.count_by_type()
    iocs_by_severity = await ioc_repo.count_by_severity()
    total_jobs = await job_repo.total_count()
    last_job_row = await job_repo.latest()
    last_job = IngestionJobResponse.model_validate(last_job_row) if last_job_row else None

    return StatsResponse(
        total_iocs=total_iocs,
        active_iocs=active_iocs,
        iocs_by_type=iocs_by_type,
        iocs_by_severity=iocs_by_severity,
        total_jobs=total_jobs,
        last_job=last_job,
    )


@router.get("/metrics", response_class=PlainTextResponse)
async def prometheus_metrics():
    """Prometheus-compatible text metrics."""
    return metrics.prometheus_text()


@router.get("/feeds")
async def list_feeds():
    from app.services.feed_registry import list_feeds
    return {"feeds": list_feeds()}