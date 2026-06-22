"""BradlyAI Whitelist Service — manage allow-list rules that suppress known-benign alerts."""
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from bradlyai.database import SessionLocal
from bradlyai.models.whitelist_entry import WhitelistEntryModel

logger = logging.getLogger("bradlyai.whitelist")


class WhitelistService:
    """CRUD + matching for allow-list rules."""

    def list_entries(self, entry_type: Optional[str] = None, enabled_only: bool = True) -> List[WhitelistEntryModel]:
        db: Session = SessionLocal()
        try:
            q = db.query(WhitelistEntryModel)
            if entry_type:
                q = q.filter(WhitelistEntryModel.entry_type == entry_type)
            if enabled_only:
                q = q.filter(WhitelistEntryModel.enabled == True)
            return q.order_by(WhitelistEntryModel.created_at.desc()).all()
        finally:
            db.close()

    def add_entry(self, entry_type: str, match_value: str, name: str = "",
                  description: str = "", match_field: Optional[str] = None,
                  match_pattern: str = "exact", severity_filter: Optional[List[str]] = None,
                  source_filter: Optional[List[str]] = None, ttl_seconds: Optional[int] = None,
                  created_by: str = "system") -> WhitelistEntryModel:
        """Add a new allow-list rule.

        entry_type: source_ip / user / process / domain / asset / alert_signature / time_window
        match_field: which field on the alert to match against. Defaults to entry_type.
        """
        if entry_type not in ("source_ip", "user", "process", "domain", "asset",
                              "alert_signature", "time_window"):
            raise ValueError(f"Invalid entry_type: {entry_type}")
        db: Session = SessionLocal()
        try:
            entry = WhitelistEntryModel(
                entry_type=entry_type,
                match_value=match_value,
                match_field=match_field or entry_type,
                match_pattern=match_pattern,
                name=name or match_value,
                description=description,
                severity_filter=severity_filter,
                source_filter=source_filter,
                ttl_seconds=ttl_seconds,
                created_by=created_by,
            )
            db.add(entry)
            db.commit()
            db.refresh(entry)
            logger.info(f"Whitelist entry added: {entry_type}={match_value} (id={entry.id})")
            return entry
        finally:
            db.close()

    def remove_entry(self, entry_id: int) -> bool:
        db: Session = SessionLocal()
        try:
            entry = db.query(WhitelistEntryModel).filter(WhitelistEntryModel.id == entry_id).first()
            if not entry:
                return False
            db.delete(entry)
            db.commit()
            return True
        finally:
            db.close()

    def toggle_entry(self, entry_id: int, enabled: bool) -> bool:
        db: Session = SessionLocal()
        try:
            entry = db.query(WhitelistEntryModel).filter(WhitelistEntryModel.id == entry_id).first()
            if not entry:
                return False
            entry.enabled = enabled
            db.commit()
            return True
        finally:
            db.close()

    def check_alert(self, alert, severity: Optional[str] = None,
                    source: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Check if an alert matches any active whitelist entry.

        Returns the matching entry dict if matched, else None.
        Records the hit (increments counter) on match.
        """
        db: Session = SessionLocal()
        try:
            entries = db.query(WhitelistEntryModel).filter(
                WhitelistEntryModel.enabled == True
            ).all()

            for entry in entries:
                # Expire if TTL passed
                if entry.ttl_seconds and entry.created_at:
                    expires_at = entry.created_at + timedelta(seconds=entry.ttl_seconds)
                    if datetime.now(timezone.utc) > expires_at.replace(tzinfo=timezone.utc):
                        continue

                # Scope filter
                if entry.severity_filter and severity and severity not in entry.severity_filter:
                    continue
                if entry.source_filter and source and source not in entry.source_filter:
                    continue

                # Field-to-value mapping
                field_value = self._get_alert_field(alert, entry.entry_type)
                if field_value is None:
                    continue

                # Match
                if self._match(field_value, entry.match_value, entry.match_pattern):
                    entry.hit_count = (entry.hit_count or 0) + 1
                    entry.last_hit_at = datetime.now(timezone.utc)
                    db.commit()
                    return {
                        "entry_id": entry.id,
                        "name": entry.name,
                        "entry_type": entry.entry_type,
                        "matched_value": field_value,
                        "rule_value": entry.match_value,
                        "description": entry.description,
                    }
            return None
        finally:
            db.close()

    def _get_alert_field(self, alert, entry_type: str):
        """Pull the relevant field from a NormalizedAlert by entry_type."""
        mapping = {
            "source_ip": getattr(alert, "source_ip", None),
            "user": getattr(alert, "user", None),
            "process": getattr(alert, "process", None),
            "domain": getattr(alert, "domain", None),
            "asset": getattr(alert, "asset", None),
            "alert_signature": getattr(alert, "signature", None),
        }
        return mapping.get(entry_type)

    def _match(self, field_value: str, rule_value: str, pattern: str) -> bool:
        if not field_value:
            return False
        if pattern == "exact":
            return field_value == rule_value
        if pattern == "wildcard":
            # Simple glob: * matches anything
            import fnmatch
            return fnmatch.fnmatch(field_value, rule_value)
        if pattern == "regex":
            import re
            try:
                return bool(re.search(rule_value, field_value))
            except re.error:
                return False
        return False


# Pre-populated with common known-benign sources
DEFAULT_ENTRIES = [
    {
        "entry_type": "source_ip", "match_value": "127.0.0.1",
        "name": "Localhost", "description": "Alerts from localhost are usually self-checks",
        "match_pattern": "exact",
    },
    {
        "entry_type": "process", "match_value": "TiWorker.exe",
        "name": "Windows Update Worker", "description": "Microsoft update process — never a threat",
        "match_pattern": "exact",
    },
    {
        "entry_type": "process", "match_value": "SignatureUpdate*",
        "name": "AV Signature Update", "description": "Antivirus signature update process",
        "match_pattern": "wildcard",
    },
    {
        "entry_type": "domain", "match_value": "*.windowsupdate.com",
        "name": "Windows Update Domains", "description": "Microsoft update domains",
        "match_pattern": "wildcard",
    },
]


def seed_defaults():
    """Seed default whitelist entries if the table is empty."""
    service = WhitelistService()
    if service.list_entries():
        return
    for entry in DEFAULT_ENTRIES:
        service.add_entry(created_by="default_seed", **entry)
    logger.info(f"Seeded {len(DEFAULT_ENTRIES)} default whitelist entries")


whitelist_service = WhitelistService()
