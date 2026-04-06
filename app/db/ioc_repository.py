"""
CTIR — IOC Repository
Centralises all database operations for the `iocs` table.
Services call the repository; routes call services.
"""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import IOCNotFoundError, IOCTypeNotFoundError
from app.core.logging import get_logger
from app.models.models import Ioc, IocType

logger = get_logger(__name__)


class IocRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._db = session

    # ── Type helpers ──────────────────────────────────────────────────────────

    async def get_type_id(self, type_name: str) -> int:
        result = await self._db.execute(
            select(IocType.id).where(IocType.name == type_name)
        )
        row = result.scalar_one_or_none()
        if row is None:
            raise IOCTypeNotFoundError(f"Unknown IOC type: '{type_name}'")
        return row

    async def get_type_name(self, type_id: int) -> str:
        result = await self._db.execute(
            select(IocType.name).where(IocType.id == type_id)
        )
        return result.scalar_one_or_none() or "other"

    async def list_types(self) -> list[IocType]:
        result = await self._db.execute(select(IocType).order_by(IocType.name))
        return list(result.scalars().all())

    # ── Read ──────────────────────────────────────────────────────────────────

    async def get_by_id(self, ioc_id: int) -> Ioc:
        result = await self._db.execute(select(Ioc).where(Ioc.id == ioc_id))
        row = result.scalar_one_or_none()
        if row is None:
            raise IOCNotFoundError(f"IOC with id={ioc_id} not found")
        return row

    async def get_by_hash(self, ioc_hash: str) -> Optional[Ioc]:
        result = await self._db.execute(
            select(Ioc).where(Ioc.ioc_hash == ioc_hash)
        )
        return result.scalar_one_or_none()

    async def list_iocs(
        self,
        ioc_type: Optional[str] = None,
        severity: Optional[str] = None,
        malware_family: Optional[str] = None,
        is_active: bool = True,
        page: int = 1,
        page_size: int = 50,
    ) -> tuple[int, list[Ioc]]:
        q = select(Ioc).where(Ioc.is_active == is_active)

        if ioc_type:
            type_id = await self.get_type_id(ioc_type)
            q = q.where(Ioc.ioc_type_id == type_id)
        if severity:
            q = q.where(Ioc.severity == severity)
        if malware_family:
            q = q.where(Ioc.malware_family.ilike(f"%{malware_family}%"))

        count_q = select(func.count()).select_from(q.subquery())
        total = (await self._db.execute(count_q)).scalar_one()

        q = q.order_by(Ioc.last_seen_at.desc()).offset((page - 1) * page_size).limit(page_size)
        rows = (await self._db.execute(q)).scalars().all()
        return total, list(rows)

    async def search(self, value: str, limit: int = 100) -> list[Ioc]:
        q = (
            select(Ioc)
            .where(Ioc.ioc_value.ilike(f"%{value}%"))
            .order_by(Ioc.last_seen_at.desc())
            .limit(limit)
        )
        result = await self._db.execute(q)
        return list(result.scalars().all())

    # ── Write ─────────────────────────────────────────────────────────────────

    async def create(self, ioc: Ioc) -> Ioc:
        self._db.add(ioc)
        await self._db.flush()
        logger.debug("ioc_created", ioc_hash=ioc.ioc_hash[:16])
        return ioc

    async def deactivate(self, ioc_id: int) -> Ioc:
        ioc = await self.get_by_id(ioc_id)
        ioc.is_active = False
        await self._db.flush()
        logger.info("ioc_deactivated", ioc_id=ioc_id)
        return ioc

    async def bulk_deactivate_expired(self) -> int:
        """Mark all IOCs past their expires_at as inactive."""
        now = datetime.now(timezone.utc)
        result = await self._db.execute(
            update(Ioc)
            .where(Ioc.expires_at <= now, Ioc.is_active == True)
            .values(is_active=False)
        )
        count = result.rowcount
        if count:
            logger.info("expired_iocs_deactivated", count=count)
        return count

    # ── Aggregates ────────────────────────────────────────────────────────────

    async def count_by_type(self) -> dict[str, int]:
        rows = (
            await self._db.execute(
                select(IocType.name, func.count(Ioc.id))
                .join(Ioc, Ioc.ioc_type_id == IocType.id)
                .group_by(IocType.name)
            )
        ).all()
        return {r[0]: r[1] for r in rows}

    async def count_by_severity(self) -> dict[str, int]:
        rows = (
            await self._db.execute(
                select(Ioc.severity, func.count(Ioc.id)).group_by(Ioc.severity)
            )
        ).all()
        return {r[0]: r[1] for r in rows}

    async def total_count(self, is_active: Optional[bool] = None) -> int:
        q = select(func.count(Ioc.id))
        if is_active is not None:
            q = q.where(Ioc.is_active == is_active)
        return (await self._db.execute(q)).scalar_one()