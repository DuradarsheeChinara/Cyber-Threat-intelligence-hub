"""Small dependency-free HS256 JWT implementation for local CTI Hub auth."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from .database import get_db
from .models import User

security = HTTPBearer(auto_error=False)
SECRET = os.getenv("JWT_SECRET", "change-me-for-production")

def password_hash(password: str) -> str:
    return hashlib.sha256(password.encode("utf-8")).hexdigest()

def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

def issue_token(username: str) -> str:
    header = _b64(b'{"alg":"HS256","typ":"JWT"}')
    payload = _b64(json.dumps({"sub": username, "exp": int(time.time()) + 86_400}).encode())
    signature = _b64(hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
    return f"{header}.{payload}.{signature}"

def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required")
    try:
        header, payload, signature = credentials.credentials.split(".")
        expected = _b64(hmac.new(SECRET.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest())
        claims = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
    except (ValueError, json.JSONDecodeError):
        raise HTTPException(status_code=401, detail="Invalid token")
    if not hmac.compare_digest(signature, expected) or claims.get("exp", 0) < time.time():
        raise HTTPException(status_code=401, detail="Invalid or expired token")
    user = db.query(User).filter(User.username == claims.get("sub")).first()
    if not user:
        raise HTTPException(status_code=401, detail="Unknown user")
    return user
