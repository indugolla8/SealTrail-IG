from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from .audit import log_event
from .auth import get_current_user
from .database import get_db
from .models import AuditLog, Document, User
from .permissions import check_access

router = APIRouter(prefix="/documents", tags=["lifecycle"])


@router.get("/deleted/list")
def list_deleted(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    docs = (db.query(Document)
              .filter(Document.owner_id == user.id, Document.deleted_at.isnot(None))
              .order_by(Document.deleted_at.desc()).all())
    return [{"id": d.id, "name": d.name, "category": d.category,
             "deleted_at": d.deleted_at} for d in docs]


@router.post("/{doc_id}/restore")
def restore(doc_id: int, user: User = Depends(get_current_user),
            db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    # Same 404 for "missing", "not yours" and "not deleted": nothing to probe.
    if doc is None or doc.owner_id != user.id or doc.deleted_at is None:
        log_event(db, user, "restore", "denied", document_id=doc_id,
                  details="not found, not owner, or not deleted")
        raise HTTPException(status_code=404, detail="Document not found")
    doc.deleted_at = None
    db.commit()
    log_event(db, user, "restore", "allowed", document_id=doc.id)
    return {"restored": True, "id": doc.id, "name": doc.name}


@router.get("/{doc_id}/history")
def history(doc_id: int, user: User = Depends(get_current_user),
            db: Session = Depends(get_db)):
    doc = check_access(db, user, doc_id, "share", "history")  # owner-only gate
    rows = (db.query(AuditLog)
              .filter(AuditLog.document_id == doc.id)
              .order_by(AuditLog.id.desc()).limit(200).all())
    return [{"time": r.timestamp, "actor": r.actor_email, "action": r.action,
             "result": r.result, "details": r.details} for r in rows]