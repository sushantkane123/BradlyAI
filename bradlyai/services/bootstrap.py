"""Idempotent first-boot seeding: tenants, roles, users, playbooks, sigma rules."""
import logging
import secrets
from sqlalchemy.orm import Session

from bradlyai.config import settings
from bradlyai.models.user import UserModel
from bradlyai.models.role import RoleModel, UserRoleModel
from bradlyai.services.password import hash_password
from bradlyai.services.auth import seed_default_roles
from bradlyai.services.tenant import seed_default_tenant
from bradlyai.services.playbook_engine import seed_builtin_playbooks
from bradlyai.services.sigma import seed_default_sigma_rules

logger = logging.getLogger("bradlyai.bootstrap")


def bootstrap_admin_user(db: Session) -> None:
    """Create the bootstrap admin if no users exist."""
    if db.query(UserModel).count() > 0:
        return
    password = settings.BOOTSTRAP_ADMIN_PASSWORD
    if not password:
        logger.error(
            "No bootstrap administrator was created because BOOTSTRAP_ADMIN_PASSWORD is empty. "
            "Set it in the deployment secret store, then restart BradlyAI."
        )
        return
    admin = UserModel(
        id=f"usr_{secrets.token_hex(6)}",
        username=settings.BOOTSTRAP_ADMIN_USERNAME,
        email=settings.BOOTSTRAP_ADMIN_EMAIL,
        full_name="Bootstrap Admin",
        password_hash=hash_password(password),
        is_active=True, is_admin=True,
        tenant_id=settings.DEFAULT_TENANT_ID,
    )
    db.add(admin)
    db.flush()
    admin_role = db.query(RoleModel).filter(RoleModel.name == "admin").first()
    if admin_role:
        db.add(UserRoleModel(user_id=admin.id, role_id=admin_role.id,
                             tenant_id=settings.DEFAULT_TENANT_ID, granted_by="bootstrap"))
    db.commit()
    logger.warning("Bootstrap administrator created for user '%s'. Rotate the configured password after first sign-in.", settings.BOOTSTRAP_ADMIN_USERNAME)


def run_all(db: Session) -> None:
    """Run every idempotent seeding step. Safe to call multiple times."""
    seed_default_tenant(db)
    seed_default_roles(db)
    bootstrap_admin_user(db)
    seed_builtin_playbooks(db)
    seed_default_sigma_rules(db)
