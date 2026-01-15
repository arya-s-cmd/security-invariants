from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Optional
from collections import defaultdict, deque

from fastapi import FastAPI, Header, HTTPException, status, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# ---- Auth model (simple on purpose, good enough for invariants testing) ----

@dataclass(frozen=True)
class Principal:
    role: str
    subject: str


ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin-token")
USER_TOKEN = os.getenv("USER_TOKEN", "user-token")

RATE_LIMIT_WINDOW_SEC = int(os.getenv("RATE_LIMIT_WINDOW_SEC", "60"))
RATE_LIMIT_MAX_FAILS = int(os.getenv("RATE_LIMIT_MAX_FAILS", "10"))
_failed_auth: dict[str, deque[float]] = defaultdict(deque)

def _client_ip(req: Request) -> str:
    xff = req.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return req.client.host if req.client else "unknown"

def _rate_limit_check(req: Request) -> None:
    ip = _client_ip(req)
    now = time.time()
    q = _failed_auth[ip]
    cutoff = now - RATE_LIMIT_WINDOW_SEC
    while q and q[0] < cutoff:
        q.popleft()
    if len(q) >= RATE_LIMIT_MAX_FAILS:
        raise HTTPException(status_code=429, detail="too many auth failures, slow down")

def _record_auth_failure(req: Request) -> None:
    ip = _client_ip(req)
    _failed_auth[ip].append(time.time())


ALLOWED_ORIGINS = [o.strip() for o in os.getenv("ALLOWED_ORIGINS", "http://localhost:5173").split(",") if o.strip()]
ALLOW_CREDENTIALS = os.getenv("ALLOW_CREDENTIALS", "false").lower() == "true"


def _principal_from_auth(authorization: Optional[str]) -> Optional[Principal]:
    if not authorization:
        return None
    if not authorization.startswith("Bearer "):
        return None
    token = authorization.removeprefix("Bearer ").strip()
    if token == ADMIN_TOKEN:
        return Principal(role="admin", subject="admin@example.com")
    if token == USER_TOKEN:
        return Principal(role="user", subject="user@example.com")
    return None


def require_auth(req: Request, p: Optional[Principal]) -> Principal:
    _rate_limit_check(req)
    if not p:
        _record_auth_failure(req)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing/invalid token")
    return p


def require_admin(p: Principal) -> None:
    if p.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="admin required")


# ---- App ----

app = FastAPI(title="Security Invariants Demo API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=ALLOW_CREDENTIALS,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
    allow_headers=["*"],
)


class ItemIn(BaseModel):
    name: str
    note: Optional[str] = None


@app.get("/health")
def health():
    return {"ok": True}


@app.get("/me")
def me(request: Request, authorization: Optional[str] = Header(default=None)):
    p = require_auth(request, _principal_from_auth(authorization))
    return {"subject": p.subject, "role": p.role}


@app.post("/items")
def create_item(request: Request, payload: ItemIn, authorization: Optional[str] = Header(default=None)):
    p = require_auth(request, _principal_from_auth(authorization))
    # pretend we saved it
    return {"id": "item_1", "owner": p.subject, "name": payload.name}


@app.get("/admin/secret")
def admin_secret(request: Request, authorization: Optional[str] = Header(default=None)):
    p = require_auth(request, _principal_from_auth(authorization))
    require_admin(p)
    return {"secret": "TOP_SECRET_VALUE"}


@app.get("/pii")
def pii(request: Request, authorization: Optional[str] = Header(default=None)):
    # should never leak PII to unauth
    _rate_limit_check(request)
    p = _principal_from_auth(authorization)
    if not p:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing/invalid token")
    # only admin sees extra PII fields
    base = {"subject": p.subject, "role": p.role}
    if p.role == "admin":
        base.update({"email": p.subject, "phone": "+1-555-0100"})
    return base
