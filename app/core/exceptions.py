"""
CTIR — Custom exception hierarchy
All domain exceptions inherit from CTIRBaseException so that the
global handler can catch them uniformly and return structured JSON.
"""

from fastapi import HTTPException, status


class CTIRBaseException(Exception):
    """Root for all CTIR domain exceptions."""
    status_code: int = 500
    detail: str = "An unexpected error occurred"

    def __init__(self, detail: str | None = None):
        self.detail = detail or self.__class__.detail
        super().__init__(self.detail)


# ── Feed / Connector ──────────────────────────────────────────────────────────

class FeedConnectionError(CTIRBaseException):
    status_code = 502
    detail = "Failed to connect to the threat feed"


class FeedAuthenticationError(CTIRBaseException):
    status_code = 401
    detail = "Feed authentication failed — check your API key"


class FeedRateLimitError(CTIRBaseException):
    status_code = 429
    detail = "Feed rate limit exceeded — retry after a short delay"


class FeedResponseError(CTIRBaseException):
    status_code = 502
    detail = "Feed returned an unexpected or malformed response"


# ── Parsing ───────────────────────────────────────────────────────────────────

class ParseError(CTIRBaseException):
    status_code = 422
    detail = "Failed to parse feed record"


class SchemaValidationError(CTIRBaseException):
    status_code = 422
    detail = "Record failed CTIR schema validation"


# ── Ingestion pipeline ────────────────────────────────────────────────────────

class IngestionAlreadyRunningError(CTIRBaseException):
    status_code = 409
    detail = "An ingestion job is already in progress"


class IngestionJobNotFoundError(CTIRBaseException):
    status_code = 404
    detail = "Ingestion job not found"


# ── IOC store ────────────────────────────────────────────────────────────────

class IOCNotFoundError(CTIRBaseException):
    status_code = 404
    detail = "IOC not found"


class IOCTypeNotFoundError(CTIRBaseException):
    status_code = 400
    detail = "Unknown IOC type"


class DeduplicationError(CTIRBaseException):
    status_code = 500
    detail = "Deduplication engine encountered an error"


# ── Database ──────────────────────────────────────────────────────────────────

class DatabaseConnectionError(CTIRBaseException):
    status_code = 503
    detail = "Database connection unavailable"


class DatabaseIntegrityError(CTIRBaseException):
    status_code = 409
    detail = "Database integrity constraint violated"


# ── Helpers ───────────────────────────────────────────────────────────────────

def to_http_exception(exc: CTIRBaseException) -> HTTPException:
    return HTTPException(status_code=exc.status_code, detail=exc.detail)