from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session

from .auth import get_current_user
from .audit import log_event
from .database import get_db
from .models import Permission, User
from .permissions import check_access

router = APIRouter(prefix="/documents", tags=["sharing"])


class ShareBody(BaseModel):
    email: str
    level: str  # "read" or "edit"


@router.post("/{doc_id}/share")
def share(doc_id: int, body: ShareBody, user: User = Depends(get_current_user),
          db: Session = Depends(get_db)):
    doc = check_access(db, user, doc_id, "share", "share")

    if body.level not in ("read", "edit"):
        raise HTTPException(status_code=400, detail="Level must be 'read' or 'edit'")

    target = db.query(User).filter(User.email == body.email).first()
    if target is None:
        log_event(db, user, "share", "denied", document_id=doc.id,
                  details=f"unknown user {body.email}")
        raise HTTPException(status_code=404, detail="User not found")
    if target.id == user.id:
        raise HTTPException(status_code=400, detail="You already own this document")
    if target.role == "admin":
        log_event(db, user, "share", "denied", document_id=doc.id,
                  details="cannot share with admin")
        raise HTTPException(status_code=400, detail="Documents cannot be shared with admins")

    perm = (db.query(Permission)
              .filter(Permission.document_id == doc.id, Permission.user_id == target.id)
              .first())
    if perm:
        perm.level = body.level
    else:
        db.add(Permission(document_id=doc.id, user_id=target.id, level=body.level))
    db.commit()
    log_event(db, user, "share", "allowed", document_id=doc.id,
              details=f"{target.email}:{body.level}")
    return {"document_id": doc.id, "shared_with": target.email, "level": body.level}


@router.get("/{doc_id}/shares")
def list_shares(doc_id: int, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    doc = check_access(db, user, doc_id, "share", "list_shares")
    rows = (db.query(Permission, User)
              .join(User, User.id == Permission.user_id)
              .filter(Permission.document_id == doc.id)
              .all())
    return [{"user_id": u.id, "email": u.email, "level": p.level} for p, u in rows]


@router.delete("/{doc_id}/share/{user_id}")
def revoke(doc_id: int, user_id: int, user: User = Depends(get_current_user),
           db: Session = Depends(get_db)):
    doc = check_access(db, user, doc_id, "share", "revoke")
    perm = (db.query(Permission)
              .filter(Permission.document_id == doc.id, Permission.user_id == user_id)
              .first())
    if perm is None:
        raise HTTPException(status_code=404, detail="No such share")
    db.delete(perm)
    db.commit()
    log_event(db, user, "revoke", "allowed", document_id=doc.id,
              details=f"user_id {user_id}")
    return {"revoked": True}