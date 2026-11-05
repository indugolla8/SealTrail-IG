from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from .database import get_db
from .auth import require_admin
from .models import AuditLog
from .audit import verify_chain

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])

@router.get("/audit")
def list_audit(db: Session = Depends(get_db)):
    rows = db.query(AuditLog).order_by(AuditLog.id.desc()).limit(200).all()
    return [
        {"id": r.id, "time": r.timestamp, "actor": r.actor_email,
         "action": r.action, "document_id": r.document_id,
         "result": r.result, "details": r.details}
        for r in rows
    ]

@router.get("/audit/verify")
def verify(db: Session = Depends(get_db)):
    return verify_chain(db)