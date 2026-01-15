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


async def check_write_requires_auth(client: httpx.AsyncClient, write_endpoints: List[Dict[str, str]]) -> List[Finding]:
    findings: List[Finding] = []
    for ep in write_endpoints:
        method = ep["method"].upper()
        path = ep["path"]

        # Try unauth write
        resp = await client.request(method, path, json={"name": "x", "note": "y"})
        if resp.status_code not in (401, 403):
            findings.append(
                Finding(
                    check="write_requires_auth",
                    severity="HIGH",
                    message=f"{method} {path} allowed without auth (expected 401/403)",
                    evidence={"status_code": resp.status_code, "body": safe_json(resp)},
                )
            )
    return findings


async def check_no_sensitive_fields_for_unauth(client: httpx.AsyncClient, sensitive_fields: List[str]) -> List[Finding]:
    findings: List[Finding] = []

    # Crawl a small known set (keep simple for v0)
    candidates = ["/health", "/me", "/pii", "/admin/secret"]

    for path in candidates:
        resp = await client.get(path)  # unauth

        # Only inspect bodies that returned successfully.
        # Error messages often contain words like "token" and that alone is not a data leak.
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


async def check_cors_not_wildcard_with_credentials(client: httpx.AsyncClient, cors_cfg: Dict[str, Any]) -> List[Finding]:
    """
    Security rule: If Access-Control-Allow-Credentials:true, then Access-Control-Allow-Origin must not be '*'
    """
    findings: List[Finding] = []
    if not cors_cfg.get("disallow_wildcard_with_credentials", True):
        return findings

    # preflight
    resp = await client.options(
        "/health",
        headers={
            "Origin": "http://evil.example",
            "Access-Control-Request-Method": "GET",
        },
    )
    acao = resp.headers.get("access-control-allow-origin", "")
    accred = resp.headers.get("access-control-allow-credentials", "").lower()

    if accred == "true" and acao.strip() == "*":
        findings.append(
            Finding(
                check="cors_wildcard_with_credentials",
                severity="HIGH",
                message="CORS misconfig: allow-credentials true with wildcard origin",
                evidence={"acao": acao, "accred": accred},
            )
        )

    return findings


def safe_json(resp: httpx.Response):
    try:
        return resp.json()
    except Exception:
        return None
