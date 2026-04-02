from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


# ── Normalized IOC (internal schema) ─────────────────────────────────────────

class NormalizedIoc(BaseModel):
    """Common CTIR schema — every feed must produce this."""
    ioc_value: str
    ioc_type: str                          # must match ioc_types.name
    malware_family: Optional[str] = None
    threat_type: Optional[str] = None
    confidence: int = Field(50, ge=0, le=100)
    severity: str = "medium"
    tags: list[str] = []
    source_ioc_id: Optional[str] = None
    first_seen_at: datetime
    last_seen_at: datetime
    expires_at: Optional[datetime] = None

    @field_validator("severity")
    @classmethod
    def validate_severity(cls, v: str) -> str:
        allowed = {"critical", "high", "medium", "low", "info"}
        if v.lower() not in allowed:
            return "medium"
        return v.lower()

    @field_validator("ioc_type")
    @classmethod
    def validate_ioc_type(cls, v: str) -> str:
        allowed = {"ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256", "email", "filename", "other"}
        return v if v in allowed else "other"


# ── API Response schemas ──────────────────────────────────────────────────────

class IocResponse(BaseModel):
    id: int
    ioc_value: str
    ioc_type: str
    malware_family: Optional[str]
    threat_type: Optional[str]
    confidence: int
    severity: str
    tags: Optional[list[str]]
    source_count: int
    first_seen_at: datetime
    last_seen_at: datetime
    expires_at: Optional[datetime]
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class IocListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: list[IocResponse]


class IngestionJobResponse(BaseModel):
    id: int
    feed_id: int
    triggered_by: str
    status: str
    records_fetched: int
    records_parsed: int
    records_valid: int
    records_invalid: int
    records_new: int
    records_updated: int
    records_dupes: int
    started_at: datetime
    finished_at: Optional[datetime]
    latency_ms: Optional[int]
    error_message: Optional[str]

    model_config = {"from_attributes": True}


class IngestionTriggerResponse(BaseModel):
    message: str
    job_id: int


class HealthResponse(BaseModel):
    status: str
    database: bool
    version: str


class StatsResponse(BaseModel):
    total_iocs: int
    active_iocs: int
    iocs_by_type: dict[str, int]
    iocs_by_severity: dict[str, int]
    total_jobs: int
    last_job: Optional[IngestionJobResponse]