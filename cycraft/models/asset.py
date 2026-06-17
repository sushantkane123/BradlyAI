"""
SQLAlchemy Models for Attack Surface Management (ASM) Assets
"""

from sqlalchemy import Column, Integer, String, ForeignKey
from sqlalchemy.orm import relationship
from cycraft.database import Base

class AssetModel(Base):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    type = Column(String) # Web Service, Cloud Storage, Network Gateway, Database Server, Kubernetes
    ip = Column(String)
    owner = Column(String)
    risk_score = Column(String) # Critical (91), High (74), Medium (45), Low (12)
    vulnerabilities = Column(Integer)
    status = Column(String) # At Risk, Vulnerable, Monitored, Secure
    last_scan = Column(String)

    findings = relationship("AssetFindingModel", back_populates="asset", cascade="all, delete-orphan")

class AssetFindingModel(Base):
    __tablename__ = "asset_findings"

    id = Column(Integer, primary_key=True, index=True)
    asset_id = Column(Integer, ForeignKey("assets.id"))
    finding_text = Column(String)

    asset = relationship("AssetModel", back_populates="findings")
