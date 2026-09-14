"""Ephemeral credential-file handling for the existing CLI workflow."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml


def write_ephemeral_account_files(
    accounts: list[dict[str, str]], work_dir: Path
) -> Path:
    """Write temporary per-account env files and an accounts YAML manifest.

    The files exist only inside the job's temporary directory. The caller must
    keep the directory private and let its context manager remove it after the
    scan. This compatibility format lets us reuse ``generate-multi`` while
    Windmill resources remain the system of record for secrets.
    """
    work_dir.mkdir(parents=True, exist_ok=True)
    entries: list[dict[str, str]] = []
    for index, account in enumerate(accounts, start=1):
        env_path = work_dir / f"account-{index}.env"
        lines = [
            f"AWS_ACCESS_KEY_ID={_quote(account['access_key_id'])}",
            f"AWS_SECRET_ACCESS_KEY={_quote(account['secret_access_key'])}",
        ]
        if account.get("session_token"):
            lines.append(f"AWS_SESSION_TOKEN={_quote(account['session_token'])}")
        env_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        try:
            os.chmod(env_path, 0o600)
        except OSError:
            # Windows workers do not consistently support POSIX permissions.
            pass
        entries.append(
            {
                "name": account["name"],
                "account_id": account["account_id"],
                "env_file": str(env_path),
            }
        )
    manifest = work_dir / "accounts.yaml"
    manifest.write_text(
        yaml.safe_dump({"accounts": entries}, sort_keys=False), encoding="utf-8"
    )
    return manifest


def _quote(value: str) -> str:
    """Quote a value safely for the repository's dotenv parser."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
