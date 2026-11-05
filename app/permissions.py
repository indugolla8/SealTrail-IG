from fastapi import HTTPException
from sqlalchemy.orm import Session
from .models import Document, Permission
from .audit import log_event

LEVEL_RANK = {"read": 1, "edit": 2}

def check_access(db: Session, user, document_id: int, needed: str, action: str) -> Document:
    """needed: read | edit | delete | share. Fresh DB lookup every time (no caching),
    so revoking access takes effect on the very next request."""
    doc = db.get(Document, document_id)
    if doc is None or doc.deleted_at is not None:
        log_event(db, user, action, "denied", document_id=document_id, details="not found")
        raise HTTPException(status_code=404, detail="Document not found")

    if doc.owner_id == user.id:
        return doc

    if needed in ("delete", "share"):
        log_event(db, user, action, "denied", document_id=document_id,
                  details=f"{needed} requires owner")
        raise HTTPException(status_code=404, detail="Document not found")

    perm = (db.query(Permission)
              .filter(Permission.document_id == document_id,
                      Permission.user_id == user.id)
              .first())
    if perm is None or LEVEL_RANK[perm.level] < LEVEL_RANK[needed]:
        log_event(db, user, action, "denied", document_id=document_id,
                  details=f"needs {needed}, has {perm.level if perm else 'none'}")
        raise HTTPException(status_code=404, detail="Document not found")
    return doc