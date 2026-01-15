from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx


@dataclass
class Finding:
    check: str
    severity: str
    message: str
    evidence: Optional[Dict[str, Any]] = None


def safe_json(resp: httpx.Response):
    try:
        return resp.json()
    except Exception:
        return None


async def check_write_requires_auth(
    client: httpx.AsyncClient,
    write_endpoints: List[Dict[str, str]],
    user_token: str,
) -> List[Finding]:
    findings: List[Finding] = []

    for ep in write_endpoints:
        method = ep["method"].upper()
        path = ep["path"]

        payload = {"name": "x", "note": "y"}

        # Unauth write should be blocked
        resp = await client.request(method, path, json=payload)
        if resp.status_code not in (401, 403):
            findings.append(
                Finding(
                    check="write_requires_auth",
                    severity="HIGH",
                    message=f"{method} {path} allowed without auth (expected 401/403)",
                    evidence={"status_code": resp.status_code, "body": safe_json(resp)},
                )
            )

        # Auth sanity: user token should not be ignored (401 means auth wiring broken)
        resp2 = await client.request(
            method,
            path,
            json=payload,
            headers={"Authorization": f"Bearer {user_token}"},
        )
        if resp2.status_code == 401:
            findings.append(
                Finding(
                    check="auth_header_effective",
                    severity="MEDIUM",
                    message=f"{method} {path} still returns 401 even with user token",
                    evidence={"status_code": resp2.status_code, "body": safe_json(resp2)},
                )
            )

    return findings


async def check_no_sensitive_fields_for_unauth(
    client: httpx.AsyncClient,
    sensitive_fields: List[str],
    scan_paths: List[str],
) -> List[Finding]:
    findings: List[Finding] = []

    for path in scan_paths:
        resp = await client.get(path)  # unauth

        # Only inspect success bodies; error strings often include words like "token"
        if resp.status_code < 200 or resp.status_code >= 300:
            continue

        body_text = resp.text.lower()
        for field in sensitive_fields:
            if field.lower() in body_text:
                findings.append(
                    Finding(
                        check="no_sensitive_fields_unauth",
                        severity="CRITICAL",
                        message=f"Unauth response from {path} contains sensitive field marker '{field}'",
                        evidence={"status_code": resp.status_code, "body": safe_json(resp) or resp.text[:500]},
                    )
                )

    return findings


async def check_cors_not_wildcard_with_credentials(
    client: httpx.AsyncClient,
    cors_cfg: Dict[str, Any],
) -> List[Finding]:
    findings: List[Finding] = []

    if not cors_cfg.get("disallow_wildcard_with_credentials", True):
        return findings

    # Preflight-like probe (simple heuristic)
    headers = {
        "Origin": "http://evil.example",
        "Access-Control-Request-Method": "GET",
        "Access-Control-Request-Headers": "authorization",
    }
    resp = await client.options("/health", headers=headers)

    allow_origin = resp.headers.get("access-control-allow-origin")
    allow_creds = resp.headers.get("access-control-allow-credentials")

    if allow_creds and allow_creds.lower() == "true" and allow_origin == "*":
        findings.append(
            Finding(
                check="cors_not_wildcard_with_credentials",
                severity="HIGH",
                message="CORS allows credentials with wildcard origin",
                evidence={"allow_origin": allow_origin, "allow_creds": allow_creds},
            )
        )

    return findings


async def check_admin_routes_require_admin(
    client: httpx.AsyncClient,
    admin_paths: List[str],
    user_token: str,
) -> List[Finding]:
    findings: List[Finding] = []
    headers = {"Authorization": f"Bearer {user_token}"}

    for path in admin_paths:
        resp = await client.get(path, headers=headers)
        if resp.status_code != 403:
            findings.append(
                Finding(
                    check="admin_routes_require_admin",
                    severity="HIGH",
                    message=f"Non-admin user could access {path} (expected 403)",
                    evidence={"status_code": resp.status_code, "body": safe_json(resp)},
                )
            )

    return findings


async def check_admin_routes_accessible_to_admin(
    client: httpx.AsyncClient,
    admin_paths: List[str],
    admin_token: str,
) -> List[Finding]:
    findings: List[Finding] = []
    headers = {"Authorization": f"Bearer {admin_token}"}

    for path in admin_paths:
        resp = await client.get(path, headers=headers)
        if resp.status_code == 401:
            findings.append(
                Finding(
                    check="admin_accessible_to_admin",
                    severity="MEDIUM",
                    message=f"Admin token got 401 on {path} (auth wiring likely broken)",
                    evidence={"status_code": resp.status_code, "body": safe_json(resp)},
                )
            )

    return findings