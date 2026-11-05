from fastapi import APIRouter, Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import jwt

from .database import get_db
from .models import User
from .security import verify_password, create_token, decode_token
from .audit import log_event

router = APIRouter(prefix="/auth", tags=["auth"])
oauth2 = OAuth2PasswordBearer(tokenUrl="/auth/login")


def get_current_user(token: str = Depends(oauth2), db: Session = Depends(get_db)) -> User:
    try:
        data = decode_token(token)
        user = db.get(User, int(data["sub"]))
    except (jwt.PyJWTError, KeyError, ValueError):
        log_event(db, None, "token_check", "denied", details="invalid or expired token")
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    if user is None:
        log_event(db, None, "token_check", "denied", details="user not found")
        raise HTTPException(status_code=401, detail="User not found")
    return user


def require_admin(user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> User:
    if user.role != "admin":
        log_event(db, user, "admin_access", "denied", details="non-admin tried an admin route")
        raise HTTPException(status_code=403, detail="Admin only")
    return user


@router.post("/login")
def login(form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == form.username).first()
    if user is None or not verify_password(form.password, user.password_hash):
        log_event(db, user, "login", "denied", actor_email=form.username)
        raise HTTPException(status_code=401, detail="Wrong email or password")
    log_event(db, user, "login", "allowed")
    return {"access_token": create_token(user.id), "token_type": "bearer"}


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "role": user.role}