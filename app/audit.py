import hashlib
import json
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from .models import AuditLog

GENESIS = "0" * 64

def _hash(prev_hash, ts, actor_id, actor_email, action, document_id, result, details):
    data = json.dumps(
        [prev_hash, ts, actor_id, actor_email, action, document_id, result, details]
    )
    return hashlib.sha256(data.encode()).hexdigest()

def log_event(db: Session, actor, action: str, result: str,
              document_id=None, details: str = "", actor_email: str = None):
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev = last.hash if last else GENESIS
    ts = datetime.now(timezone.utc).replace(tzinfo=None)
    actor_id = actor.id if actor else None
    email = actor.email if actor else actor_email
    row = AuditLog(
        timestamp=ts, actor_id=actor_id, actor_email=email, action=action,
        document_id=document_id, result=result, details=details,
        prev_hash=prev,
        hash=_hash(prev, ts.isoformat(), actor_id, email, action,
                   document_id, result, details),
    )
    db.add(row)
    db.commit()

def verify_chain(db: Session):
    prev = GENESIS
    for row in db.query(AuditLog).order_by(AuditLog.id).all():
        expected = _hash(prev, row.timestamp.isoformat(), row.actor_id,
                         row.actor_email, row.action, row.document_id,
                         row.result, row.details)
        if row.prev_hash != prev or row.hash != expected:
            return {"valid": False, "broken_at_id": row.id}
        prev = row.hash
    return {"valid": True, "broken_at_id": None}