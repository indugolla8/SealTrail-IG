import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt

_env_key = os.getenv("SECRET_KEY")
if _env_key:
    SECRET_KEY = _env_key
elif os.getenv("SEALTRAIL_ENV", "dev") == "dev":
    # Random per process: tokens stop working on restart, but nobody can forge them.
    SECRET_KEY = secrets.token_hex(32)
else:
    raise RuntimeError("SECRET_KEY must be set when SEALTRAIL_ENV is not 'dev'")

ALGORITHM = "HS256"


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()


def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode(), hashed.encode())


def create_token(user_id: int) -> str:
    payload = {
        "sub": str(user_id),
        "exp": datetime.now(timezone.utc) + timedelta(hours=2),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str):
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])