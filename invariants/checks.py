from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx


@dataclass
class Finding:
    check: str
    severity: str
    message: str
    evidence: Dict[str, Any] | None = None


def _safe_json(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return {"text": resp.text[:500]}


def _auth_headers(token: Optional[str], header_name: str = "Authorization") -> Dict[str, str]:
    """Build auth headers for either Authorization Bearer or API-key style headers."""
    if not token:
        return {}

    # If user explicitly wants Authorization, use Bearer style.
    if header_name.lower() == "authorization":
        return {"Authorization": f"Bearer {token}"}

    # Otherwise treat it like an API key header (X-API-Key, X-Token, etc.)
    return {header_name: token}


async def check_write_requires_auth(
    client: httpx.AsyncClient,
    write_endpoints: List[str],
    user_token: Optional[str] = None,
    auth_header: str = "Authorization",
) -> List[Finding]:
    """Write endpoints should reject unauth requests; and accept auth headers when provided."""
    findings: List[Finding] = []

    for ep in write_endpoints:
        # ep may be:
        # - "METHOD /path"
        # - "/path"
        # - {"method": "POST", "path": "/items"}
        if isinstance(ep, dict):
            method = str(ep.get("method", "POST")).strip().upper()
            path = str(ep.get("path", "")).strip()
        else:
            ep_s = str(ep).strip()
            if " " in ep_s:
                method, path = ep_s.split(" ", 1)
                method = method.strip().upper()
                path = path.strip()
            else:
                method, path = "POST", ep_s

        # Unauth should not succeed
        resp = await client.request(method, path)
        if 200 <= resp.status_code < 300:
            findings.append(
                Finding(
                    check="write_requires_auth",
                    severity="CRITICAL",
                    message=f"{method} {path} allowed write without auth",
                    evidence={"status_code": resp.status_code, "body": _safe_json(resp)},
                )
            )

        # With a user token, it should not look like "missing header"
        if user_token:
            resp2 = await client.request(method, path, headers=_auth_headers(user_token, auth_header))

            # This specific signal indicates we didn't send the right header at all
            body = _safe_json(resp2)
            detail = ""
            if isinstance(body, dict):
                detail = str(body.get("detail", ""))

            if resp2.status_code == 401 and ("required" in detail.lower() or "missing" in detail.lower()):
                findings.append(
                    Finding(
                        check="auth_header_effective",
                        severity="MEDIUM",
                        message=f"{method} {path} still returns 401 and appears to be missing auth header",
                        evidence={"status_code": resp2.status_code, "body": body},
                    )
                )

    return findings


async def check_no_sensitive_fields_for_unauth(
    client: httpx.AsyncClient,
    sensitive_fields: List[str],
    scan_paths: Optional[List[str]] = None,
) -> List[Finding]:
    """
    Scan only SUCCESSFUL (2xx) unauth responses for sensitive field markers.
    This avoids false positives like error bodies mentioning 'token'.
    """
    findings: List[Finding] = []
    scan_paths = scan_paths or []

    for path in scan_paths:
        resp = await client.get(path)
        if not (200 <= resp.status_code < 300):
            continue  # Only inspect successful unauth responses

        body = _safe_json(resp)
        body_str = json.dumps(body, ensure_ascii=False).lower()

        for marker in (m.lower() for m in sensitive_fields):
            if marker and marker in body_str:
                findings.append(
                    Finding(
                        check="no_sensitive_fields_unauth",
                        severity="CRITICAL",
                        message=f"Unauth response from {path} contains sensitive field marker '{marker}'",
                        evidence={"status_code": resp.status_code, "body": body},
                    )
                )

    return findings


async def check_admin_routes_require_admin(
    client: httpx.AsyncClient,
    admin_paths: List[str],
    user_token: str,
    auth_header: str = "Authorization",
) -> List[Finding]:
    """
    Non-admin user should get 401/403 on admin endpoints.
    404 is treated as 'route not present' and skipped.
    """
    findings: List[Finding] = []
    headers = _auth_headers(user_token, auth_header)

    for path in admin_paths:
        resp = await client.get(path, headers=headers)

        if resp.status_code == 404:
            continue  # not present in this deployment

        if resp.status_code not in (401, 403):
            findings.append(
                Finding(
                    check="admin_routes_require_admin",
                    severity="HIGH",
                    message=f"Non-admin user could access {path} (expected 403)",
                    evidence={"status_code": resp.status_code, "body": _safe_json(resp)},
                )
            )

    return findings


async def check_admin_routes_accessible_to_admin(
    client: httpx.AsyncClient,
    admin_paths: List[str],
    admin_token: str,
    auth_header: str = "Authorization",
) -> List[Finding]:
    """
    Admin token should be accepted on admin endpoints.
    404 is treated as 'route not present' and skipped.
    """
    findings: List[Finding] = []
    headers = _auth_headers(admin_token, auth_header)

    for path in admin_paths:
        resp = await client.get(path, headers=headers)

        if resp.status_code == 404:
            continue

        if resp.status_code == 401:
            findings.append(
                Finding(
                    check="admin_routes_accessible_to_admin",
                    severity="MEDIUM",
                    message=f"Admin token not accepted for {path}",
                    evidence={"status_code": resp.status_code, "body": _safe_json(resp)},
                )
            )

    return findings


async def check_cors_not_wildcard_with_credentials(
    client: httpx.AsyncClient,
    cors_cfg: Dict[str, Any],
) -> List[Finding]:
    """
    Minimal CORS sanity check: if allow_credentials is true, allow_origins should not be '*'.
    This check is config-driven (does not depend on live server behavior).
    """
    findings: List[Finding] = []
    allow_credentials = bool(cors_cfg.get("allow_credentials"))
    allow_origins = cors_cfg.get("allow_origins")

    if allow_credentials and allow_origins == "*":
        findings.append(
            Finding(
                check="cors_not_wildcard_with_credentials",
                severity="HIGH",
                message="CORS allow_credentials=true with allow_origins='*' is unsafe",
                evidence={"cors": cors_cfg},
            )
        )

    return findings