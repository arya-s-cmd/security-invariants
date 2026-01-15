from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import httpx
import yaml

from invariants.checks import (
    check_cors_not_wildcard_with_credentials,
    check_no_sensitive_fields_for_unauth,
    check_write_requires_auth,
)


@dataclass
class Finding:
    check: str
    severity: str
    message: str
    evidence: Optional[Dict[str, Any]] = None


def load_app(app_ref: str):
    """
    app_ref: "module.path:app"
    """
    mod, attr = app_ref.split(":", 1)
    m = importlib.import_module(mod)
    return getattr(m, attr)


def load_config(path: str = "invariants.yml") -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


async def run_all(config_path: str = "invariants.yml") -> List[Finding]:
    cfg = load_config(config_path)
    app = load_app(cfg["target"]["app"])

    admin_token = cfg["auth"]["admin_token"]
    user_token = cfg["auth"]["user_token"]
    sensitive_fields = cfg.get("sensitive_fields", [])
    write_eps = cfg.get("write_endpoints", [])
    cors_cfg = cfg.get("cors", {})

    findings: List[Finding] = []

    transport = httpx.ASGITransport(app=app)

    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:

        findings += await check_write_requires_auth(client, write_eps)
        findings += await check_no_sensitive_fields_for_unauth(client, sensitive_fields)
        findings += await check_cors_not_wildcard_with_credentials(client, cors_cfg)

    return findings
