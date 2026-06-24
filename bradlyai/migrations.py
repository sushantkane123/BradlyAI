"""BradlyAI — Lightweight in-place schema migrations.

Handles new tables (create_all) + new columns (ALTER TABLE) on existing DBs.
"""
import logging
from sqlalchemy import inspect, text
from sqlalchemy.engine import Engine

logger = logging.getLogger("bradlyai.migrations")


def get_table_columns(engine: Engine, table_name: str) -> set:
    inspector = inspect(engine)
    if table_name not in inspector.get_table_names():
        return set()
    return {col["name"] for col in inspector.get_columns(table_name)}


def get_model_columns(model) -> dict:
    from sqlalchemy import inspect as sqla_inspect
    mapper = sqla_inspect(model)
    return {col.key: col for col in mapper.columns}


def ensure_column(engine: Engine, table_name: str, column_name: str, column) -> bool:
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
    from bradlyai.models.alert import AlertModel
    from bradlyai.models.audit_log import AuditLogModel
    from bradlyai.models.whitelist_entry import WhitelistEntryModel
    from bradlyai.models.feedback import FeedbackModel
    from bradlyai.models.user import UserModel
    from bradlyai.models.role import RoleModel, PermissionModel, UserRoleModel
    from bradlyai.models.api_key import ApiKeyModel
    from bradlyai.models.tenant import TenantModel
    from bradlyai.models.case import CaseModel, CaseNoteModel, CaseEvidenceModel
    from bradlyai.models.playbook import PlaybookModel, PlaybookRunModel
    from bradlyai.models.notification_log import NotificationLogModel
    from bradlyai.models.sigma_rule import SigmaRuleModel

    added = []

    # AlertModel: existing columns + tenant_id, case_id, assignee, playbook_id
    for col_name in ("signature", "closed_at", "closed_reason", "closed_by",
                     "tenant_id", "case_id", "assigned_to", "playbook_id"):
        col = AlertModel.__table__.c[col_name]
        if ensure_column(engine, "alerts", col_name, col):
            added.append(f"alerts.{col_name}")

    # User / Role / Permission / UserRole — full tables (create_all handles)
    # Case / CaseNote / CaseEvidence
    for model, table_name in [
        (CaseModel, "cases"), (CaseNoteModel, "case_notes"), (CaseEvidenceModel, "case_evidence"),
        (PlaybookModel, "playbooks"), (PlaybookRunModel, "playbook_runs"),
        (NotificationLogModel, "notification_log"),
        (SigmaRuleModel, "sigma_rules"),
        (UserModel, "users"), (RoleModel, "roles"),
        (PermissionModel, "permissions"), (UserRoleModel, "user_roles"),
        (ApiKeyModel, "api_keys"), (TenantModel, "tenants"),
        (AuditLogModel, "audit_log"),
        (WhitelistEntryModel, "whitelist_entries"),
        (FeedbackModel, "feedback"),
    ]:
        existing = get_table_columns(engine, table_name)
        if not existing:
            continue     # create_all handles new tables
        for col_name, col in get_model_columns(model).items():
            if ensure_column(engine, table_name, col_name, col):
                added.append(f"{table_name}.{col_name}")

    return {"added_columns": added, "count": len(added)}


def run_migrations_and_create(engine: Engine, base) -> dict:
    base.metadata.create_all(engine)
    return run_migrations(engine)
