"""
CTIR — IOC Service
Business logic for IOC retrieval, deactivation, expiry management.
Routes depend on this; this depends on IocRepository.
"""

from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logging import get_logger
from app.db.ioc_repository import IocRepository
from app.models.models import Ioc, IocType
from app.schemas.schemas import IocListResponse, IocResponse

logger = get_logger(__name__)


def _to_response(ioc: Ioc, type_name: str) -> IocResponse:
    return IocResponse(
        id=ioc.id,
        ioc_value=ioc.ioc_value,
        ioc_type=type_name,
        malware_family=ioc.malware_family,
        threat_type=ioc.threat_type,
        confidence=ioc.confidence,
        severity=ioc.severity,
        tags=ioc.tags or [],
        source_count=ioc.source_count,
        first_seen_at=ioc.first_seen_at,
        last_seen_at=ioc.last_seen_at,
        expires_at=ioc.expires_at,
        is_active=ioc.is_active,
        created_at=ioc.created_at,
    )


class IocService:
    def __init__(self, session: AsyncSession) -> None:
        self._repo = IocRepository(session)

    async def get(self, ioc_id: int) -> IocResponse:
        ioc = await self._repo.get_by_id(ioc_id)
        type_name = await self._repo.get_type_name(ioc.ioc_type_id)
        return _to_response(ioc, type_name)

    async def list_iocs(
        self,
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
        malware_family: Optional[str] = None,
        is_active: bool = True,
        page: int = 1,
        page_size: int = 50,
    ) -> IocListResponse:
        total, rows = await self._repo.list_iocs(
            ioc_type=ioc_type,
            severity=severity,
            malware_family=malware_family,
            is_active=is_active,
            page=page,
            page_size=page_size,
        )
        items = []
        for row in rows:
            type_name = await self._repo.get_type_name(row.ioc_type_id)
            items.append(_to_response(row, type_name))
        return IocListResponse(total=total, page=page, page_size=page_size, items=items)

    async def search(self, value: str) -> IocListResponse:
        rows = await self._repo.search(value)
        items = []
        for row in rows:
            type_name = await self._repo.get_type_name(row.ioc_type_id)
            items.append(_to_response(row, type_name))
        return IocListResponse(total=len(items), page=1, page_size=100, items=items)

    async def deactivate(self, ioc_id: int) -> IocResponse:
        ioc = await self._repo.deactivate(ioc_id)
        type_name = await self._repo.get_type_name(ioc.ioc_type_id)
        return _to_response(ioc, type_name)

    async def expire_stale(self) -> int:
        """Deactivate all IOCs past their expires_at timestamp."""
        return await self._repo.bulk_deactivate_expired()

    async def list_types(self) -> list[dict]:
        types = await self._repo.list_types()
        return [{"id": t.id, "name": t.name, "description": t.description} for t in types]