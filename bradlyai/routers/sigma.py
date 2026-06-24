"""Sigma rules router — import / list / evaluate."""
import os
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File
from pydantic import BaseModel
from sqlalchemy.orm import Session

from bradlyai.config import settings
from bradlyai.database import get_db
from bradlyai.models.sigma_rule import SigmaRuleModel
from bradlyai.models.user import UserModel
from bradlyai.services.auth import require_permission
from bradlyai.services.sigma import (
    evaluate_event, import_rule_file, import_rule_directory,
    load_yaml_rule, seed_default_sigma_rules,
)

router = APIRouter(prefix="/sigma", tags=["Sigma Rules"])


class EvaluateRequest(BaseModel):
    event: Dict[str, Any]


class ImportPathRequest(BaseModel):
    path: str


@router.get("")
def list_rules(level: Optional[str] = None, product: Optional[str] = None,
               enabled: Optional[bool] = None, limit: int = 200,
               db: Session = Depends(get_db),
               _: UserModel = Depends(require_permission("detection", "read"))):
    q = db.query(SigmaRuleModel)
    if level:
        q = q.filter(SigmaRuleModel.level == level)
    if product:
        q = q.filter(SigmaRuleModel.logsource_product == product)
    if enabled is not None:
        q = q.filter(SigmaRuleModel.enabled == enabled)
    return [{
        "id": r.id, "title": r.title, "level": r.level, "status": r.status,
        "logsource_product": r.logsource_product, "logsource_category": r.logsource_category,
        "tags": r.tags_json, "enabled": r.enabled,
        "author": r.author, "date": r.date.isoformat() if r.date else None,
    } for r in q.limit(limit).all()]


@router.post("/evaluate")
def evaluate(req: EvaluateRequest, db: Session = Depends(get_db),
             _: UserModel = Depends(require_permission("detection", "read"))):
    return evaluate_event(db, req.event)


@router.post("/import/file")
async def import_file(file: UploadFile = File(...), db: Session = Depends(get_db),
                      _: UserModel = Depends(require_permission("detection", "write"))):
    text = (await file.read()).decode("utf-8")
    rule = load_yaml_rule(text)
    if rule is None:
        raise HTTPException(status_code=400, detail="Invalid Sigma YAML")
    existing = db.query(SigmaRuleModel).filter(SigmaRuleModel.id == rule.id).first()
    if existing:
        for attr in ("title", "description", "level", "status", "detection_json",
                     "tags_json", "enabled"):
            setattr(existing, attr, getattr(rule, attr))
        db.commit()
        return {"status": "updated", "id": existing.id}
    db.add(rule)
    db.commit()
    return {"status": "imported", "id": rule.id}


@router.post("/import/path")
def import_path(req: ImportPathRequest, db: Session = Depends(get_db),
                _: UserModel = Depends(require_permission("detection", "write"))):
    if not os.path.isdir(req.path):
        raise HTTPException(status_code=400, detail="Path is not a directory")
    imported, failed = import_rule_directory(db, req.path)
    return {"imported": imported, "failed": failed}


@router.post("/seed-defaults",
             dependencies=[Depends(require_permission("detection", "write"))])
def seed_defaults(db: Session = Depends(get_db)):
    count = seed_default_sigma_rules(db)
    return {"seeded": count}
