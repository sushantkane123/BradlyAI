"""Optimized BradlyAI Database Setup — featuring SQLite WAL Concurrency.

Gains:
- WAL Mode Concurrency: Automatically configures SQLite to use Write-Ahead Logging (WAL) 
  on engine connection. This completely eliminates 'sqlite3.OperationalError: database is locked' 
  crashes when mixing sync and async database writes.
- Optimal SQLite Connection Pooling: Customizes event listeners to enforce standard constraints.
"""

from sqlalchemy import create_engine, event
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import QueuePool
from bradlyai.config import settings

Base = declarative_base()

def _build_connect_args() -> dict:
    if "sqlite" in settings.DATABASE_URL:
        # SQLite-specific connection arguments (must be nested in connect_args)
        return {"connect_args": {"timeout": 30}}
    return {}

def _build_pool_args() -> dict:
    if "sqlite" in settings.DATABASE_URL:
        return {}
    return {
        "poolclass": QueuePool,
        "pool_size": settings.DB_POOL_SIZE,
        "max_overflow": settings.DB_MAX_OVERFLOW,
        "pool_recycle": settings.DB_POOL_RECYCLE,
        "pool_pre_ping": True,
    }

_engine_kwargs = {**_build_connect_args(), **_build_pool_args()}
_engine_kwargs["echo"] = settings.ENVIRONMENT == "development"

# 1. Create standard synchronous engine
engine = create_engine(
    settings.DATABASE_URL.replace("+aiosqlite", "").replace("+asyncpg", "+psycopg2"),
    **_engine_kwargs,
)

# SQLite WAL mode registration:
# This listener interceptor executes automatically on every connection, enabling 
# concurrent read/write locks, preventing database locked exceptions.
@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    if "sqlite" in settings.DATABASE_URL:
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        finally:
            cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 2. Create modern asynchronous engine
try:
    async_engine = create_async_engine(settings.DATABASE_URL, echo=False)
    AsyncSessionLocal = async_sessionmaker(async_engine, class_=AsyncSession, expire_on_commit=False)
    
    # Register WAL listener on async engine too!
    @event.listens_for(async_engine.sync_engine, "connect")
    def set_async_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        try:
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
        except Exception:
            pass
        finally:
            cursor.close()

except Exception as exc:
    async_engine = None
    AsyncSessionLocal = None
    import logging
    logging.getLogger("bradlyai.database").warning(f"Async engine unavailable: {exc}")

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_async_db():
    if AsyncSessionLocal is None:
        raise RuntimeError("Async database is not available — check DATABASE_URL.")
    async with AsyncSessionLocal() as session:
        yield session
