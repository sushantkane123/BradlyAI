"""RBAC roles & permissions."""
import datetime
from sqlalchemy import Column, String, Integer, ForeignKey, Boolean, DateTime, UniqueConstraint
from sqlalchemy.orm import relationship
from bradlyai.database import Base


class RoleModel(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True, nullable=False)        # e.g. "admin", "analyst_l1"
    description = Column(String, nullable=True)
    is_builtin = Column(Boolean, default=False, nullable=False)            # cannot be deleted
    tenant_id = Column(String, index=True, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))

    permissions = relationship("PermissionModel", back_populates="role", cascade="all, delete-orphan")
    user_links = relationship("UserRoleModel", back_populates="role", cascade="all, delete-orphan")


class PermissionModel(Base):
    __tablename__ = "permissions"
    id = Column(Integer, primary_key=True, index=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False)
    resource = Column(String, nullable=False, index=True)      # "alerts", "cases", "playbooks", "settings"
    action = Column(String, nullable=False, index=True)        # "read", "write", "delete", "approve"
    role = relationship("RoleModel", back_populates="permissions")

    __table_args__ = (UniqueConstraint("role_id", "resource", "action", name="uq_role_resource_action"),)


class UserRoleModel(Base):
    __tablename__ = "user_roles"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role_id = Column(Integer, ForeignKey("roles.id", ondelete="CASCADE"), nullable=False, index=True)
    tenant_id = Column(String, index=True, nullable=True)
    granted_at = Column(DateTime, default=lambda: datetime.datetime.now(datetime.timezone.utc))
    granted_by = Column(String, nullable=True)

    user = relationship("UserModel", backref="role_links")
    role = relationship("RoleModel", back_populates="user_links")

    __table_args__ = (UniqueConstraint("user_id", "role_id", "tenant_id", name="uq_user_role_tenant"),)
