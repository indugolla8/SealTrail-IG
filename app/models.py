from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, UniqueConstraint
from .database import Base

def now():
    return datetime.now(timezone.utc)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False)  # admin / owner / viewer

class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    category = Column(String)
    stored_name = Column(String, nullable=False)  # random name on disk
    mime_type = Column(String)
    size = Column(Integer)
    created_at = Column(DateTime, default=now)
    deleted_at = Column(DateTime, nullable=True)

class Permission(Base):
    __tablename__ = "permissions"
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    level = Column(String, nullable=False)  # read / edit
    __table_args__ = (UniqueConstraint("document_id", "user_id"),)

class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=now)
    actor_id = Column(Integer, nullable=True)
    actor_email = Column(String, nullable=True)
    action = Column(String, nullable=False)
    document_id = Column(Integer, nullable=True)
    result = Column(String, nullable=False)  # allowed / denied
    details = Column(String)
    prev_hash = Column(String, nullable=False)
    hash = Column(String, nullable=False)