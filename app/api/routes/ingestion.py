import asyncio

from fastapi import APIRouter, BackgroundTasks, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import IngestionJobNotFoundError, to_http_exception
from app.db.database import get_db
from app.db.job_repository import IngestionJobRepository
from app.schemas.schemas import IngestionJobResponse, IngestionTriggerResponse

router = APIRouter(prefix="/ingestion", tags=["Ingestion"])

# Give a fast API response while running a long process in background
@router.post("/trigger", response_model=IngestionTriggerResponse, status_code=202)
async def trigger_ingestion(background_tasks: BackgroundTasks):
    """Manually trigger a ThreatFox ingestion cycle (async, returns immediately)."""
    from app.services.ingestion_service import run_ingestion, _is_running
    from app.core.exceptions import IngestionAlreadyRunningError

    if _is_running:
        raise to_http_exception(IngestionAlreadyRunningError())

    loop = asyncio.get_event_loop()
    future: asyncio.Future = loop.create_future()

    async def _run():
        try:
            result = await run_ingestion(triggered_by="manual")
            if not future.done():
                future.set_result(result.id)
        except Exception as exc:
            if not future.done():
                future.set_exception(exc)

    background_tasks.add_task(_run)

    try:
        job_id = await asyncio.wait_for(asyncio.shield(future), timeout=10.0)
    except asyncio.TimeoutError:
        job_id = -1

    return IngestionTriggerResponse(message="Ingestion job started", job_id=job_id)


@router.get("/jobs", response_model=list[IngestionJobResponse])
async def list_jobs(limit: int = Query(20, ge=1, le=100), db: AsyncSession = Depends(get_db)):
    """List recent ingestion jobs, newest first."""
    repo = IngestionJobRepository(db)
    jobs = await repo.list_recent(limit=limit)
    return [IngestionJobResponse.model_validate(j) for j in jobs]
# model_validate takes raw data (dict / ORM object)
# converts into model
# validates fields


@router.get("/jobs/{job_id}", response_model=IngestionJobResponse)
async def get_job(job_id: int, db: AsyncSession = Depends(get_db)):
    """Fetch a specific ingestion job by ID."""
    repo = IngestionJobRepository(db)
    try:
        job = await repo.get_by_id(job_id)
        return IngestionJobResponse.model_validate(job)
    except IngestionJobNotFoundError as exc:
        raise to_http_exception(exc)


@router.get("/jobs/{job_id}/errors")
async def get_job_errors(
    job_id: int,
    limit: int = Query(100, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    """Return parse errors recorded during a specific ingestion job."""
    repo = IngestionJobRepository(db)
    try:
        await repo.get_by_id(job_id)
    except IngestionJobNotFoundError as exc:
        raise to_http_exception(exc)

    errors = await repo.list_parse_errors(job_id, limit=limit)
    return {
        "job_id": job_id,
        "count": len(errors),
        "errors": [
            {
                "id": e.id,
                "error_type": e.error_type,
                "error_msg": e.error_msg,
                "raw_data": e.raw_data,
                "created_at": e.created_at,
            }
            for e in errors
        ],
    }