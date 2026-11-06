import os
import uuid
from datetime import date, datetime, time, timezone
from typing import Optional

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .auth import get_current_user
from .audit import log_event
from .database import get_db
from .models import Document, Permission, User
from .permissions import check_access

router = APIRouter(prefix="/documents", tags=["documents"])

UPLOAD_DIR = "uploads"
MAX_SIZE = 5 * 1024 * 1024  # 5 MB
ALLOWED = {".pdf": "application/pdf", ".png": "image/png",
           ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".txt": "text/plain"}
MAGIC = {".pdf": b"%PDF", ".png": b"\x89PNG", ".jpg": b"\xff\xd8", ".jpeg": b"\xff\xd8"}

os.makedirs(UPLOAD_DIR, exist_ok=True)


def doc_json(d: Document):
    return {"id": d.id, "name": d.name, "owner_id": d.owner_id,
            "category": d.category, "size": d.size, "mime_type": d.mime_type,
            "created_at": d.created_at}


@router.post("")
async def upload(file: UploadFile = File(...), category: str = Form(""),
                 user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role != "owner":
        log_event(db, user, "upload", "denied", details="role cannot upload")
        raise HTTPException(status_code=403, detail="Only owners can upload")

    name = os.path.basename(file.filename or "")
    ext = os.path.splitext(name)[1].lower()
    if not name or ext not in ALLOWED:
        log_event(db, user, "upload", "denied", details=f"bad file type: {ext}")
        raise HTTPException(status_code=400, detail="File type not allowed")

    data = await file.read(MAX_SIZE + 1)
    if len(data) > MAX_SIZE:
        log_event(db, user, "upload", "denied", details="file too large")
        raise HTTPException(status_code=413, detail="File too large (max 5 MB)")
    if len(data) == 0:
        raise HTTPException(status_code=400, detail="Empty file")
    if ext in MAGIC and not data.startswith(MAGIC[ext]):
        log_event(db, user, "upload", "denied", details="content does not match extension")
        raise HTTPException(status_code=400, detail="File content does not match its type")

    stored = uuid.uuid4().hex
    with open(os.path.join(UPLOAD_DIR, stored), "wb") as f:
        f.write(data)

    doc = Document(name=name, owner_id=user.id, category=category, stored_name=stored,
                   mime_type=ALLOWED[ext], size=len(data))
    db.add(doc)
    db.commit()
    log_event(db, user, "upload", "allowed", document_id=doc.id, details=name)
    return doc_json(doc)


@router.get("")
def list_documents(name: Optional[str] = None, owner: Optional[str] = None,
                   category: Optional[str] = None,
                   date_from: Optional[date] = None, date_to: Optional[date] = None,
                   user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    shared = db.query(Permission.document_id).filter(Permission.user_id == user.id)
    q = db.query(Document).filter(
        Document.deleted_at.is_(None),
        or_(Document.owner_id == user.id, Document.id.in_(shared)),
    )
    if name:
        q = q.filter(Document.name.ilike(f"%{name}%"))
    if category:
        q = q.filter(Document.category.ilike(f"%{category}%"))
    if owner:
        q = q.join(User, User.id == Document.owner_id).filter(User.email.ilike(f"%{owner}%"))
    if date_from:
        q = q.filter(Document.created_at >= datetime.combine(date_from, time.min))
    if date_to:
        q = q.filter(Document.created_at <= datetime.combine(date_to, time.max))
    return [doc_json(d) for d in q.order_by(Document.id.desc()).all()]


@router.get("/{doc_id}/download")
def download(doc_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = check_access(db, user, doc_id, "read", "download")
    log_event(db, user, "download", "allowed", document_id=doc.id)
    return FileResponse(os.path.join(UPLOAD_DIR, doc.stored_name),
                        media_type=doc.mime_type, filename=doc.name)


class EditBody(BaseModel):
    name: Optional[str] = None
    category: Optional[str] = None


@router.put("/{doc_id}")
def edit(doc_id: int, body: EditBody, user: User = Depends(get_current_user),
         db: Session = Depends(get_db)):
    doc = check_access(db, user, doc_id, "edit", "edit")
    if body.name:
        new_name = os.path.basename(body.name)
        old_ext = os.path.splitext(doc.name)[1].lower()
        new_ext = os.path.splitext(new_name)[1].lower()
        if new_ext != old_ext or new_ext not in ALLOWED:
            log_event(db, user, "edit", "denied", document_id=doc.id,
                      details=f"rename changes extension: {old_ext} -> {new_ext}")
            raise HTTPException(status_code=400,
                                detail="New name must keep the original file extension")
        doc.name = new_name
    if body.category is not None:
        doc.category = body.category
    db.commit()
    log_event(db, user, "edit", "allowed", document_id=doc.id)
    return doc_json(doc)


@router.delete("/{doc_id}")
def delete(doc_id: int, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = check_access(db, user, doc_id, "delete", "delete")
    doc.deleted_at = datetime.now(timezone.utc).replace(tzinfo=None)
    db.commit()
    log_event(db, user, "delete", "allowed", document_id=doc.id)
    return {"deleted": True}