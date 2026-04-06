from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import IOCNotFoundError, IOCTypeNotFoundError, to_http_exception
from app.db.database import get_db
from app.schemas.schemas import IocListResponse, IocResponse
from app.services.enrichment_service import enrich_ioc
from app.services.ioc_service import IocService

router = APIRouter(prefix="/iocs", tags=["IOCs"])


@router.get("", response_model=IocListResponse)
async def list_iocs(
    ioc_type: Optional[str] = Query(None, description="ip | domain | url | hash_md5 | hash_sha256 ..."),
    severity: Optional[str] = Query(None, description="critical | high | medium | low | info"),
    malware_family: Optional[str] = Query(None),
    is_active: bool = Query(True),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    db: AsyncSession = Depends(get_db),
):
    svc = IocService(db)
    try:
        return await svc.list_iocs(
            ioc_type=ioc_type,
            severity=severity,
            malware_family=malware_family,
            is_active=is_active,
            page=page,
            page_size=page_size,
        )
    except IOCTypeNotFoundError as exc:
        raise to_http_exception(exc)


@router.get("/types", response_model=list[dict])
async def list_ioc_types(db: AsyncSession = Depends(get_db)):
    svc = IocService(db)
    return await svc.list_types()


@router.get("/search/{value}", response_model=IocListResponse)
async def search_ioc(value: str, db: AsyncSession = Depends(get_db)):
    svc = IocService(db)
    return await svc.search(value)


@router.get("/enrich/{value}")
async def enrich(value: str):
    result = await enrich_ioc(value)
    return {
        "ioc_value": result.ioc_value,
        "found": result.found,
        "count": len(result.records),
        "records": [r.model_dump() for r in result.records],
    }


@router.get("/{ioc_id}", response_model=IocResponse)
async def get_ioc(ioc_id: int, db: AsyncSession = Depends(get_db)):
    svc = IocService(db)
    try:
        return await svc.get(ioc_id)
    except IOCNotFoundError as exc:
        raise to_http_exception(exc)


@router.delete("/{ioc_id}", response_model=IocResponse)
async def deactivate_ioc(ioc_id: int, db: AsyncSession = Depends(get_db)):
    svc = IocService(db)
    try:
        return await svc.deactivate(ioc_id)
    except IOCNotFoundError as exc:
        raise to_http_exception(exc)