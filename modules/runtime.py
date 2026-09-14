"""Runtime and input normalization helpers for Windmill jobs."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any


def ensure_package_importable() -> Path:
    """Find the repository root and make the source package available.

    Windmill deployments may sync this folder as a code repository, while
    container deployments may install ``aws-ri`` as a package. Supporting both
    layouts makes local testing and Windmill deployment use the same entry
    point.
    """
    current = Path(__file__).resolve()
    candidates = [current.parents[2], Path.cwd(), Path.cwd().parent]
    for candidate in candidates:
        if (candidate / "src" / "aws_ri").is_dir():
            source = str(candidate / "src")
            if source not in os.sys.path:
                os.sys.path.insert(0, source)
            return candidate
    raise RuntimeError(
        "Could not locate the aws-ri source package. Sync the repository or "
        "install aws-ri in the Windmill worker image."
    )


def normalize_accounts(accounts: list[dict[str, Any]]) -> list[dict[str, str]]:
    """Validate Windmill account-resource input without exposing secrets."""
    normalized: list[dict[str, str]] = []
    for index, raw in enumerate(accounts, start=1):
        if not isinstance(raw, dict):
            raise ValueError(f"Account entry {index} must be an object")
        required = ("account_id", "access_key_id", "secret_access_key")
        missing = [key for key in required if not str(raw.get(key, "")).strip()]
        if missing:
            raise ValueError(
                f"Account entry {index} is missing required fields: {', '.join(missing)}"
            )
        account_id = str(raw["account_id"]).strip()
        if len(account_id) != 12 or not account_id.isdigit():
            raise ValueError(f"Account entry {index} has an invalid account_id")
        normalized.append(
            {
                "name": str(raw.get("name") or account_id).strip(),
                "account_id": account_id,
                "access_key_id": str(raw["access_key_id"]).strip(),
                "secret_access_key": str(raw["secret_access_key"]).strip(),
                "session_token": str(raw.get("session_token") or "").strip(),
            }
        )
    return normalized
