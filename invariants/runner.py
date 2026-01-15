from __future__ import annotations

import importlib
from typing import Any, Dict, List, Optional

import httpx
import yaml

from invariants.checks import (
    Finding,
    check_admin_routes_accessible_to_admin,
    check_admin_routes_require_admin,
    check_cors_not_wildcard_with_credentials,
    check_no_sensitive_fields_for_unauth,
    check_write_requires_auth,
)


def load_app(app_ref: str):
    mod, attr = app_ref.split(":", 1)
    m = importlib.import_module(mod)
    return getattr(m, attr)


def load_config(path: str = "invariants.yml") -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _require(cfg: Dict[str, Any], dotted: str) -> Any:
    cur: Any = cfg
    for part in dotted.split("."):
        if not isinstance(cur, dict) or part not in cur:
            raise ValueError(f"Missing required config key: {dotted}")
        cur = cur[part]
    return cur


def validate_config(cfg: Dict[str, Any]) -> None:
    _require(cfg, "target.app")
    _require(cfg, "auth.admin_token")
    _require(cfg, "auth.user_token")

    cfg.setdefault("sensitive_fields", ["email", "phone", "secret", "password", "api_key", "token"])
    cfg.setdefault("cors", {"disallow_wildcard_with_credentials": True})


def _is_noise_path(path: str) -> bool:
    return path.startswith(("/docs", "/redoc", "/openapi"))


def discover_endpoints(openapi: Dict[str, Any]) -> Dict[str, Any]:
    paths = openapi.get("paths", {}) or {}

    write_eps: List[Dict[str, str]] = []
    admin_paths: List[str] = []
    unauth_scan_paths: List[str] = []

    for path, methods in paths.items():
        if not isinstance(methods, dict):
            continue
        if _is_noise_path(path):
            continue

        if path.startswith("/admin"):
            admin_paths.append(path)

        for method in methods.keys():
            m = method.upper()
            if m in ("POST", "PUT", "PATCH", "DELETE"):
                write_eps.append({"method": m, "path": path})
            elif m == "GET":
                unauth_scan_paths.append(path)

    admin_paths = sorted(set(admin_paths))
    unauth_scan_paths = sorted(set(unauth_scan_paths))

    dedup = sorted({(e["method"], e["path"]) for e in write_eps})
    write_eps = [{"method": m, "path": p} for (m, p) in dedup]

    return {
        "write_endpoints": write_eps,
        "admin_paths": admin_paths,
        "unauth_scan_paths": unauth_scan_paths,
    }


async def run_all(config_path: str = "invariants.yml", base_url: Optional[str] = None) -> List[Finding]:
    cfg = load_config(config_path)
    validate_config(cfg)

    app = load_app(cfg["target"]["app"])

    admin_token = cfg["auth"]["admin_token"]
    user_token = cfg["auth"]["user_token"]
    auth_header = cfg.get("auth", {}).get("header", "Authorization")
    sensitive_fields = cfg.get("sensitive_fields", [])
    cors_cfg = cfg.get("cors", {})

    # Two modes:
    # 1) In-process ASGI (fast tests): base_url is None
    # 2) Live server over HTTP (realistic): base_url provided
    if base_url:
        bu = base_url.rstrip("/")
        async with httpx.AsyncClient(base_url=bu, timeout=15.0, follow_redirects=True) as client:
            openapi_resp = await client.get("/openapi.json")
            if openapi_resp.status_code != 200:
                return [
                    Finding(
                        check="openapi_available",
                        severity="HIGH",
                        message="Could not fetch /openapi.json (required for auto-discovery)",
                        evidence={"status_code": openapi_resp.status_code, "body": openapi_resp.text[:500]},
                    )
                ]

            discovered = discover_endpoints(openapi_resp.json())
            write_eps = discovered["write_endpoints"]
            admin_paths = discovered["admin_paths"] or cfg.get("admin_paths", ["/admin/secret"])
            scan_paths = discovered["unauth_scan_paths"] or ["/health"]

            findings: List[Finding] = []
            findings += await check_write_requires_auth(client, write_eps, user_token=user_token, auth_header=auth_header)
            findings += await check_no_sensitive_fields_for_unauth(client, sensitive_fields, scan_paths=scan_paths)
            findings += await check_admin_routes_require_admin(client, admin_paths, user_token=user_token, auth_header=auth_header)
            findings += await check_admin_routes_accessible_to_admin(client, admin_paths, admin_token=admin_token, auth_header=auth_header)
            findings += await check_cors_not_wildcard_with_credentials(client, cors_cfg)
            return findings


    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test", timeout=15.0) as client:
        openapi_resp = await client.get("/openapi.json")
        if openapi_resp.status_code != 200:
            return [
                Finding(
                    check="openapi_available",
                    severity="HIGH",
                    message="Could not fetch /openapi.json (required for auto-discovery)",
                    evidence={"status_code": openapi_resp.status_code, "body": openapi_resp.text[:500]},
                )
            ]

        discovered = discover_endpoints(openapi_resp.json())

        write_eps = discovered["write_endpoints"]
        admin_paths = discovered["admin_paths"] or cfg.get("admin_paths", ["/admin/secret"])
        scan_paths = discovered["unauth_scan_paths"] or ["/health"]

        findings: List[Finding] = []
        findings += await check_write_requires_auth(client, write_eps, user_token=user_token, auth_header=auth_header)
        findings += await check_no_sensitive_fields_for_unauth(client, sensitive_fields, scan_paths=scan_paths)
        findings += await check_admin_routes_require_admin(client, admin_paths, user_token=user_token, auth_header=auth_header)
        findings += await check_admin_routes_accessible_to_admin(client, admin_paths, admin_token=admin_token, auth_header=auth_header)
        findings += await check_cors_not_wildcard_with_credentials(client, cors_cfg)
        return findings