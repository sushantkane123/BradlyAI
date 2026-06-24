"""BradlyAI Database Setup (SQLAlchemy sync + async).

Supports both SQLite (development / single-node demo) and Postgres
(production). Connection args / pool sizing switch automatically based
on the URL scheme.
"""
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import QueuePool
from bradlyai.config import settings

Base = declarative_base()


def _build_connect_args() -> dict:
    """Return engine-specific connect args."""
    if "sqlite" in settings.DATABASE_URL:
        return {}
    return {}


def _build_pool_args() -> dict:
    """Pool sizing only applies to non-SQLite backends."""
    if "sqlite" in settings.DATABASE_URL:
        return {"poolclass": None}
    return {
        "poolclass": QueuePool,
        "pool_size": settings.DB_POOL_SIZE,
        "max_overflow": settings.DB_MAX_OVERFLOW,
        "pool_recycle": settings.DB_POOL_RECYCLE,
        "pool_pre_ping": True,
    }


_engine_kwargs = {**_build_connect_args(), **_build_pool_args()}
# Echo only in development
_engine_kwargs["echo"] = settings.ENVIRONMENT == "development"

# Sync engine (used by FastAPI dependency, migrations, CLI tools)
engine = create_engine(
    settings.DATABASE_URL.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg2"),
    **_engine_kwargs,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Async engine (used by async routers / workers)
try:
    async_engine = create_async_engine(settings.DATABASE_URL, echo=False)
    AsyncSessionLocal = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)
except Exception as exc:  # pragma: no cover
    async_engine = None
    AsyncSessionLocal = None
    import logging
    logging.getLogger("bradlyai.database").warning(f"Async engine unavailable: {exc}")


def get_db():
    """FastAPI dependency yielding a sync Session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


async def get_async_db():
    """FastAPI dependency yielding an async Session."""
    if AsyncSessionLocal is None:
        raise RuntimeError("Async database is not available — check DATABASE_URL.")
    async with AsyncSessionLocal() as session:
        yield session
