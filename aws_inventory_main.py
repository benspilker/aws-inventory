"""Windmill entry point for multi-account AWS Resource Inventory scans.

This is intentionally a thin orchestration layer. The tested collectors and
report writers remain in :mod:`aws_ri`; Windmill supplies inputs, scheduling,
secret storage, and artifact delivery.

Windmill can call ``main`` directly. Account entries should be supplied from a
Windmill Resource or secret-backed variable, not hard-coded in this file.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    from .modules.artifacts import upload_artifacts
    from .modules.credentials import write_ephemeral_account_files
    from .modules.runtime import ensure_package_importable, normalize_accounts
except ImportError:
    # Windmill commonly executes a script file directly rather than importing
    # the repository as a Python package.
    from modules.artifacts import upload_artifacts
    from modules.credentials import write_ephemeral_account_files
    from modules.runtime import ensure_package_importable, normalize_accounts


def _file_size(path: Path) -> dict[str, Any]:
    """Return stable machine-readable and human-readable artifact size data."""
    size_bytes = path.stat().st_size
    size = float(size_bytes)
    units = ("B", "KB", "MB", "GB")
    unit = units[0]
    for candidate in units:
        unit = candidate
        if size < 1024 or candidate == units[-1]:
            break
        size /= 1024
    return {"size_bytes": size_bytes, "size": f"{size:.2f} {unit}"}


def main(
    accounts: list[dict[str, Any]],
    days: int = 30,
    regions: list[str] | None = None,
    output_prefix: str = "aws-resource-inventory",
    s3_bucket: str | None = None,
    s3_prefix: str | None = None,
    include_inventory: bool = True,
    include_costs: bool = True,
    include_posture: bool = True,
    lite: bool = False,
) -> dict[str, Any]:
    """Run the existing account-local/multi-account workflow in Windmill.

    Each account dictionary requires ``account_id`` and credential fields
    ``access_key_id``, ``secret_access_key``, and optionally ``session_token``.
    ``name`` is optional. Credentials are materialized only in the worker's
    temporary directory and removed when the job finishes.
    """
    if not accounts:
        raise ValueError("accounts must contain at least one account")
    if days <= 0:
        raise ValueError("days must be positive")

    repo_root = ensure_package_importable()
    normalized = normalize_accounts(accounts)
    with tempfile.TemporaryDirectory(prefix="aws-ri-windmill-") as temp_dir:
        work = Path(temp_dir)
        accounts_file = write_ephemeral_account_files(normalized, work)
        output_path = work / f"{output_prefix}.xlsx"

        command = [
            sys.executable,
            "-m",
            "aws_ri.cli.main",
            "generate-multi",
            "--accounts-file",
            str(accounts_file),
            "--out",
            str(output_path),
        ]
        if regions:
            command.extend(["--regions", ",".join(regions)])
        if not include_inventory:
            command.append("--no-inventory")
        if not include_costs:
            command.append("--no-costs")
        if not include_posture:
            command.append("--no-posture")
        if lite:
            command.append("--lite")
        command.extend(["--days", str(days)])

        environment = os.environ.copy()
        environment["PYTHONPATH"] = os.pathsep.join(
            [str(repo_root / "src"), environment.get("PYTHONPATH", "")]
        ).rstrip(os.pathsep)
        completed = subprocess.run(
            command,
            cwd=repo_root,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )
        if completed.returncode:
            # CLI output is useful for Windmill logs, but credentials are never
            # included in the command or emitted by this wrapper.
            raise RuntimeError(
                "AWS inventory scan failed with exit code "
                f"{completed.returncode}: {completed.stderr[-4000:]}"
            )

        artifacts = [output_path]
        drawio_path = output_path.with_suffix(".drawio")
        if drawio_path.exists():
            artifacts.append(drawio_path)
        excel_size = _file_size(output_path)
        print(f"AWS inventory Excel report: {output_path} ({excel_size['size_bytes']:,} bytes; {excel_size['size']})")
        result: dict[str, Any] = {
            "status": "completed",
            "accounts": [account["account_id"] for account in normalized],
            "days": days,
            "regions": regions or "all enabled regions",
            "artifacts": [str(path) for path in artifacts],
            "excel_file": {"path": str(output_path), **excel_size},
            "cli_output": completed.stdout[-4000:],
        }
        if s3_bucket:
            result["uploaded_artifacts"] = upload_artifacts(
                artifacts, s3_bucket, s3_prefix or output_prefix
            )
        return json.loads(json.dumps(result, default=str))
