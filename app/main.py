from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Optional

from fastapi import FastAPI, Header, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


# ---- Auth model (simple on purpose, good enough for invariants testing) ----

@dataclass(frozen=True)
class Principal:
    role: str
    subject: str


ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "admin-token")
USER_TOKEN = os.getenv("USER_TOKEN", "user-token")

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


def require_auth(p: Optional[Principal]) -> Principal:
    if not p:
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
def me(authorization: Optional[str] = Header(default=None)):
    p = require_auth(_principal_from_auth(authorization))
    return {"subject": p.subject, "role": p.role}


@app.post("/items")
def create_item(payload: ItemIn, authorization: Optional[str] = Header(default=None)):
    p = require_auth(_principal_from_auth(authorization))
    # pretend we saved it
    return {"id": "item_1", "owner": p.subject, "name": payload.name}


@app.get("/admin/secret")
def admin_secret(authorization: Optional[str] = Header(default=None)):
    p = require_auth(_principal_from_auth(authorization))
    require_admin(p)
    return {"secret": "TOP_SECRET_VALUE"}


@app.get("/pii")
def pii(authorization: Optional[str] = Header(default=None)):
    # should never leak PII to unauth
    p = _principal_from_auth(authorization)
    if not p:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="missing/invalid token")
    # only admin sees extra PII fields
    base = {"subject": p.subject, "role": p.role}
    if p.role == "admin":
        base.update({"email": p.subject, "phone": "+1-555-0100"})
    return base
