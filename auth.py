
import os
import sqlite3
import jwt

from datetime import datetime, timedelta, timezone
from pwdlib import PasswordHash
from fastapi import HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from database import get_connection

password_hash = PasswordHash.recommended()

SECRET_KEY = os.environ.get("TRUSTVAULT_SECRET_KEY")

if not SECRET_KEY:
    raise RuntimeError(
        "Set TRUSTVAULT_SECRET_KEY before starting the app"
    )

ALGORITHM = "HS256"
oauth2_scheme = HTTPBearer()

def hash_password(password: str) -> str:
    return password_hash.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    return password_hash.verify(password, stored_hash)


def create_access_token(user_id: int, role: str) -> str:
    now = datetime.now(timezone.utc)

    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=15)
    }

    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(oauth2_scheme)
):
    token = credentials.credentials

    try:
        payload = jwt.decode(
            token,
            SECRET_KEY,
            algorithms=[ALGORITHM]
        )
        user_id = int(payload["sub"])
    except (jwt.InvalidTokenError, KeyError, ValueError):
        raise HTTPException(
            status_code=401,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )

    connection = get_connection()

    try:
        user = connection.execute(
            "SELECT id, username, role FROM users WHERE id = ?",
            (user_id,)
        ).fetchone()
    finally:
        connection.close()

    if user is None:
        raise HTTPException(status_code=401, detail="User not found")

    return dict(user)

