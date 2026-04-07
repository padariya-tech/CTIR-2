"""
CTIR Adapter Layer — Query Filter Schema
All adapter endpoints accept these query parameters.
The AdapterQueryFilter is resolved from FastAPI Query() params
and passed down to the IOC repository / adapter service.
"""

from datetime import datetime
from typing import Optional
from fastapi import Query
from pydantic import BaseModel, Field


# Sentinel — keeps FastAPI Query defaults DRY
_Q = Query


class AdapterQueryFilter(BaseModel):
    """
    Unified filter model for all adapter output endpoints.

    Consumers set whichever fields are relevant; unset fields are ignored.
    """

    # ── Type / Classification ────────────────────────────────────────────────
    ioc_type: Optional[str] = Field(
        None,
        description="ip | domain | url | hash_md5 | hash_sha1 | hash_sha256 | email | filename | other",
    )
    severity: Optional[str] = Field(
        None,
        description="critical | high | medium | low | info",
    )
    malware_family: Optional[str] = Field(
        None, description="Partial match on malware family name"
    )
    threat_type: Optional[str] = Field(
        None, description="Partial match on threat type"
    )

    # ── Confidence ───────────────────────────────────────────────────────────
    min_confidence: int = Field(
        0, ge=0, le=100, description="Minimum confidence score (0-100)"
    )
    max_confidence: int = Field(
        100, ge=0, le=100, description="Maximum confidence score (0-100)"
    )

    # ── Time range ───────────────────────────────────────────────────────────
    first_seen_after: Optional[datetime] = Field(
        None, description="IOC first seen after this datetime (ISO 8601)"
    )
    first_seen_before: Optional[datetime] = Field(
        None, description="IOC first seen before this datetime (ISO 8601)"
    )
    last_seen_after: Optional[datetime] = Field(
        None, description="IOC last seen after this datetime (ISO 8601)"
    )
    last_seen_before: Optional[datetime] = Field(
        None, description="IOC last seen before this datetime (ISO 8601)"
    )

    # ── Source ───────────────────────────────────────────────────────────────
    source_feed_id: Optional[int] = Field(
        None, description="Filter by primary feed ID"
    )

    # ── Active / expired ─────────────────────────────────────────────────────
    is_active: bool = Field(True, description="Return only active IOCs")

    # ── Pagination ───────────────────────────────────────────────────────────
    page: int = Field(1, ge=1, description="Page number (1-based)")
    page_size: int = Field(200, ge=1, le=5000, description="Records per page")

    # ── Tags ─────────────────────────────────────────────────────────────────
    tag: Optional[str] = Field(
        None, description="Filter by tag (exact match inside tags JSON array)"
    )


def adapter_query_params(
    ioc_type: Optional[str] = _Q(None),
    severity: Optional[str] = _Q(None),
    malware_family: Optional[str] = _Q(None),
    threat_type: Optional[str] = _Q(None),
    min_confidence: int = _Q(0, ge=0, le=100),
    max_confidence: int = _Q(100, ge=0, le=100),
    first_seen_after: Optional[datetime] = _Q(None),
    first_seen_before: Optional[datetime] = _Q(None),
    last_seen_after: Optional[datetime] = _Q(None),
    last_seen_before: Optional[datetime] = _Q(None),
    source_feed_id: Optional[int] = _Q(None),
    is_active: bool = _Q(True),
    page: int = _Q(1, ge=1),
    page_size: int = _Q(200, ge=1, le=5000),
    tag: Optional[str] = _Q(None),
) -> AdapterQueryFilter:
    """FastAPI dependency that assembles AdapterQueryFilter from query params."""
    return AdapterQueryFilter(
        ioc_type=ioc_type,
        severity=severity,
        malware_family=malware_family,
        threat_type=threat_type,
        min_confidence=min_confidence,
        max_confidence=max_confidence,
        first_seen_after=first_seen_after,
        first_seen_before=first_seen_before,
        last_seen_after=last_seen_after,
        last_seen_before=last_seen_before,
        source_feed_id=source_feed_id,
        is_active=is_active,
        page=page,
        page_size=page_size,
        tag=tag,
    )