# Security Invariants — Automated Security Guarantees for APIs

Security Invariants is a lightweight framework that continuously verifies **non-negotiable security properties** of an API using its OpenAPI spec — without writing endpoint-by-endpoint tests.

It enforces rules like:
- **Writes must require authentication**
- **Admin routes must reject non-admin callers**
- **Public GETs must not leak sensitive fields**
- **Rate limiting must trigger after repeated auth failures**
- **CORS must be safe when credentials are enabled**

This repository contains:
- a **FastAPI reference API** (used to demonstrate the checks), and
- a **config-driven invariant runner** that can run **offline (ASGI)** or **against a live deployment (HTTP)**.

---

## Why this matters

Most API security failures are **systemic**:
- one router/middleware change can expose multiple endpoints
- teams ship endpoints faster than they ship security reviews
- “we have auth” isn’t a guarantee unless you *test it continuously*

Security Invariants turns expectations into executable checks that fail CI when guarantees are broken.

---

## What it checks (current invariants)

### 1) Auth required on write endpoints
Any non-GET endpoint (POST/PUT/PATCH/DELETE) must **not succeed** without authorization.

### 2) Admin authorization on privileged endpoints
Endpoints under configured admin paths must:
- reject unauthenticated requests
- reject authenticated non-admin requests
- allow admin requests

### 3) No sensitive fields in unauthenticated successful GETs
Unauthenticated `GET` endpoints that return `2xx` are scanned for sensitive indicators (configurable markers such as `email`, `phone`, `token`, `ssn`).

### 4) Rate limiting after repeated auth failures
After `N` failed auth attempts, the service must start returning `429`.

### 5) CORS sanity rule
Detect unsafe CORS configurations such as `allow_credentials=true` with wildcard origins.

---

## Architecture (high level)

1. Fetch `/openapi.json`
2. Classify endpoints using config rules (writes, admin, public GETs)
3. Execute invariant checks (unauth / user / admin)
4. Report violations (fail CI if any)

---

## Quickstart

### Install

    python -m venv .venv
    source .venv/bin/activate      # macOS/Linux
    # .venv\Scripts\activate       # Windows

    pip install -r requirements.txt

### Run the reference API

    uvicorn app.main:app --reload --port 8000

OpenAPI:
- http://127.0.0.1:8000/openapi.json

---

## Run invariants

### Option A — Offline mode (fast, deterministic)
Runs the app in-process for repeatable tests.

    python -m invariants.cli --config invariants.yml

### Option B — Live-server mode (real HTTP, validates deployment behavior)
Run the server first (above), then:

    python -m invariants.cli --config invariants.yml --base-url http://127.0.0.1:8000

Use this mode to validate real deployment behavior (proxy headers, CORS responses, auth middleware, real rate limiting, etc.).

---

## Authentication used in the reference API

The reference API uses bearer tokens to demonstrate invariants:

- **User token:** `user-token`
- **Admin token:** `admin-token`

Examples:

    curl -H "Authorization: Bearer user-token"  http://127.0.0.1:8000/me
    curl -H "Authorization: Bearer admin-token" http://127.0.0.1:8000/admin/secret

Override via env vars:

    export USER_TOKEN="..."
    export ADMIN_TOKEN="..."

---

## Configuration (`invariants.yml`)

This file defines:
- how to identify admin routes
- which tokens to use for user/admin roles
- sensitive field markers
- rate limiting expectations
- CORS safety expectations

Example:

    base:
      openapi_path: /openapi.json

    auth:
      user_token: user-token
      admin_token: admin-token

    admin:
      paths:
        - /admin

    sensitive_scan:
      enabled: true
      markers:
        - email
        - phone
        - token
        - ssn

    rate_limit:
      enabled: true
      max_unauth_attempts: 10
      expect_status: 429

    cors:
      disallow_wildcard_with_credentials: true

---

## Extending with your own invariants

Real-world high-signal extensions:
- **Tenant isolation**: a user from tenant A can’t read tenant B (BOLA/IDOR regression)
- **RBAC drift detection**: route policy must match role requirements
- **Header hardening**: validate HSTS / X-Content-Type-Options / CSP (where applicable)
- **Object-level authorization**: verify access control on resource IDs
- **Negative tests**: schema/validation rejection for malformed input

The goal: make security assumptions executable and continuously enforced.

---

## CI

CI runs the invariant suite to catch regressions automatically.  
For real services, run invariants against staging using `--base-url`.
