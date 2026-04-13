from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.exceptions import CTIRBaseException
from app.core.logging import get_logger, setup_logging
from app.core.scheduler import start_scheduler, stop_scheduler
from app.core.security import RequestIDMiddleware
from app.api.routes import iocs, ingestion, system
from app.adapters.routes.export import router as adapter_router

setup_logging()
logger = get_logger(__name__)
settings = get_settings()

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("ctir_startup", version=settings.API_VERSION)
    start_scheduler()
    yield
    stop_scheduler()
    logger.info("ctir_shutdown")


app = FastAPI(
    title=settings.API_TITLE,
    version=settings.API_VERSION,
    description=(
        "Central Threat Intelligence Repository — "
        "ingestion pipeline powered by ThreatFox"
    ),
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

# ── Middleware ────────────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(RequestIDMiddleware)

# ── Domain exception handler ──────────────────────────────────────────────────
@app.exception_handler(CTIRBaseException) # catch all CTIR domain exceptions and return structured JSON
async def ctir_exception_handler(request: Request, exc: CTIRBaseException):
    logger.warning(
        "ctir_domain_exception",
        path=request.url.path,
        error=exc.detail,
        status_code=exc.status_code,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )

# ── Global fallback handler ───────────────────────────────────────────────────
@app.exception_handler(Exception) # handle any uncaught exceptions to prevent 500s without logs
async def unhandled_exception_handler(request: Request, exc: Exception):
    logger.error(
        "unhandled_exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(system.router)
app.include_router(iocs.router, prefix="/api/v1")
app.include_router(ingestion.router, prefix="/api/v1")
app.include_router(adapter_router, prefix="/api/v1")

@app.get("/", include_in_schema=False)
async def root():
    return {
        "service": "CTIR",
        "version": settings.API_VERSION,
        "docs": "/docs",
    }