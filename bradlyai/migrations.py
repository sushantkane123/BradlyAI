"""BradlyAI — Lightweight in-place schema migrations.

SQLAlchemy's ``Base.metadata.create_all()`` only creates NEW tables — it does
NOT add new columns to existing tables. This module detects missing columns
in existing tables and runs ``ALTER TABLE`` to add them, preserving data.

For a brand-new database, ``create_all()`` is sufficient. For an existing
database with new columns added to models, this module catches up.
"""
import logging
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

logger = logging.getLogger("bradlyai.migrations")


def get_table_columns(engine: Engine, table_name: str) -> set:
    """Return the set of column names currently in the table."""
    inspector = inspect(engine)
    if table_name not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns(table_name)}


def get_model_columns(model) -> dict:
    """Return {column_name: sqlalchemy_column} for the given ORM model."""
    from sqlalchemy import inspect as sqla_inspect
    mapper = sqla_inspect(model)
    return {col.key: col for col in mapper.columns}


def ensure_column(engine: Engine, table_name: str, column_name: str, column) -> bool:
    """Add a column to a table if it doesn't exist. Returns True if added."""
    existing = get_table_columns(engine, table_name)
    if column_name in existing:
        return False
    col_type = column.type.compile(engine.dialect)
    nullable = "NULL" if column.nullable else "NOT NULL"
    default = ""
    if column.default is not None and column.default.arg is not None:
        default_val = column.default.arg
        if isinstance(default_val, str):
            default = f" DEFAULT '{default_val}'"
        else:
            default = f" DEFAULT {default_val}"
    sql = f'ALTER TABLE {table_name} ADD COLUMN {column_name} {col_type} {nullable}{default}'
    with engine.begin() as conn:
        conn.execute(text(sql))
    logger.info(f"Added column {table_name}.{column_name} ({col_type})")
    return True


def run_migrations(engine: Engine) -> dict:
    """Run all pending in-place migrations. Returns summary."""
    from bradlyai.models.alert import AlertModel
    from bradlyai.models.asset import AssetModel
    from bradlyai.models.audit_log import AuditLogModel
    from bradlyai.models.whitelist_entry import WhitelistEntryModel
    from bradlyai.models.feedback import FeedbackModel

    added = []

    # AlertModel: signature, closed_at, closed_reason, closed_by
    for col_name in ("signature", "closed_at", "closed_reason", "closed_by"):
        col = AlertModel.__table__.c[col_name]
        if ensure_column(engine, "alerts", col_name, col):
            added.append(f"alerts.{col_name}")

    # AssetModel: any new fields (placeholder for future)
    # (no changes needed currently)

    # New tables — already handled by create_all() below
    for model, table_name in [
        (AuditLogModel, "audit_log"),
        (WhitelistEntryModel, "whitelist_entries"),
        (FeedbackModel, "feedback"),
    ]:
        existing = get_table_columns(engine, table_name)
        if not existing:
            # create_all will handle creating the table; skip
            continue
        for col_name, col in get_model_columns(model).items():
            if ensure_column(engine, table_name, col_name, col):
                added.append(f"{table_name}.{col_name}")

    return {"added_columns": added, "count": len(added)}


def run_migrations_and_create(engine: Engine, base) -> dict:
    """Combined: create any missing tables, then add any missing columns."""
    # 1. Create any missing tables
    base.metadata.create_all(engine)
    # 2. Add any missing columns to existing tables
    return run_migrations(engine)
