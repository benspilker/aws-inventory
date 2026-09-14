#requirements:
#boto3>=1.28.0
#click>=8.1.0
#xlsxwriter>=3.1.0
#pyyaml>=6.0

"""Slim Windmill entry point that clones the application source at runtime.

Deploy this file as a Windmill script. It clones the configured Git repository
into the worker's temporary directory and loads the application package from
that checkout. No local repository files are required by the runner.
"""

from __future__ import annotations

import json
import base64
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


DEFAULT_REPOSITORY_URL = "https://github.com/benspilker/aws-inventory.git"
SOURCE_REF = "main"
SCAN_DAYS = 30
DEFAULT_REGION = "us-east-1"
OUTPUT_PREFIX = "aws-resource-inventory"
S3_BUCKET = ""
S3_PREFIX = "aws-resource-inventory"
AWS_TEMP_KEYS_VARIABLE = "u/bspilker/aws-temp-keys"
GITLAB_REPOSITORY_VARIABLE = "u/bspilker/aws-inventory-scan-gitlab-repository-url"
GITLAB_TOKEN_VARIABLE = "u/bspilker/aws-inventory-scan-gitlab"


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


def _clone_modules(repository_url: str, source_ref: str | None, runtime: Path) -> Path:
    """Clone the source repository and return its Python package path."""
    checkout = runtime / "aws-inventory"
    command = ["git", "clone", "--depth", "1"]
    if source_ref:
        command.extend(["--branch", source_ref])
    command.extend([repository_url, str(checkout)])
    completed = subprocess.run(command, capture_output=True, text=True, check=False)
    if completed.returncode:
        raise RuntimeError(
            "Unable to clone the AWS inventory repository. "
            f"git exited with {completed.returncode}: {completed.stderr[-2000:]}"
        )
    candidates = [checkout / "modules", checkout / "src"]
    for candidate in candidates:
        if (candidate / "aws_ri" / "__init__.py").is_file():
            return candidate
    raise RuntimeError("The cloned repository does not contain modules/aws_ri or src/aws_ri")


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _parse_account_ids(accounts: str) -> list[str]:
    """Parse and validate the single Windmill accounts textbox."""
    values = [value.strip() for value in accounts.split(",") if value.strip()]
    if not values:
        raise ValueError("Enter one or more comma-separated AWS account IDs")
    invalid = [value for value in values if len(value) != 12 or not value.isdigit()]
    if invalid:
        raise ValueError(f"Invalid AWS account ID(s): {', '.join(invalid)}")
    return list(dict.fromkeys(values))


def _windmill_variable(path: str) -> str:
    """Retrieve a Windmill variable through the SDK or API fallback."""
    try:
        import wmill

        value = wmill.get_variable(path)
        if value:
            return str(value).strip()
    except Exception:
        pass
    base_url = (os.getenv("BASE_INTERNAL_URL") or os.getenv("WM_BASE_URL") or "").rstrip("/")
    workspace = os.getenv("WM_WORKSPACE", "").strip()
    token = os.getenv("WM_TOKEN", "").strip()
    if not (base_url and workspace and token):
        raise RuntimeError(f"Unable to retrieve Windmill variable {path}")
    api_base = base_url if base_url.endswith("/api") else f"{base_url}/api"
    url = f"{api_base}/w/{workspace}/variables/get_value/{path}"
    request = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(request, timeout=15) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (urllib.error.URLError, urllib.error.HTTPError) as error:
        raise RuntimeError(f"Unable to retrieve Windmill variable {path}: {error}") from error
    value = payload.get("value") if isinstance(payload, dict) else payload
    if not value:
        raise RuntimeError(f"Windmill variable {path} is empty")
    return str(value).strip()


def _credentials_from_variable(account_ids: list[str]) -> list[dict[str, str]]:
    """Decode the base64 AWS export block and verify its account identity."""
    import boto3

    encoded = "".join(_windmill_variable(AWS_TEMP_KEYS_VARIABLE).split())
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except Exception as error:
        raise RuntimeError(f"Windmill variable {AWS_TEMP_KEYS_VARIABLE} is not valid base64") from error
    values = {}
    for raw_line in decoded.splitlines():
        line = raw_line.strip()
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    required = ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN")
    missing = [key for key in required if not values.get(key)]
    if missing:
        raise RuntimeError(f"Windmill variable {AWS_TEMP_KEYS_VARIABLE} is missing: {', '.join(missing)}")
    session = boto3.Session(
        aws_access_key_id=values["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=values["AWS_SECRET_ACCESS_KEY"],
        aws_session_token=values["AWS_SESSION_TOKEN"],
        region_name=DEFAULT_REGION,
    )
    actual_id = session.client("sts").get_caller_identity()["Account"]
    if any(account_id != actual_id for account_id in account_ids):
        raise RuntimeError(
            f"Credentials from {AWS_TEMP_KEYS_VARIABLE} belong to account {actual_id}; "
            f"requested accounts are {', '.join(account_ids)}"
        )
    return [{"name": actual_id, "account_id": actual_id,
             "access_key_id": values["AWS_ACCESS_KEY_ID"],
             "secret_access_key": values["AWS_SECRET_ACCESS_KEY"],
             "session_token": values["AWS_SESSION_TOKEN"]}]


def _write_credentials(accounts: list[dict[str, Any]], directory: Path) -> Path:
    """Materialize temporary credentials for the existing multi-account CLI."""
    import yaml

    if not accounts:
        raise ValueError("accounts must contain at least one account")
    entries = []
    for number, account in enumerate(accounts, start=1):
        account_id = str(account.get("account_id", "")).strip()
        if len(account_id) != 12 or not account_id.isdigit():
            raise ValueError(f"Invalid account_id at accounts[{number - 1}]")
        for field in ("access_key_id", "secret_access_key"):
            if not str(account.get(field, "")).strip():
                raise ValueError(f"Missing {field} at accounts[{number - 1}]")
        env_file = directory / f"account-{number}.env"
        lines = [
            f"AWS_ACCESS_KEY_ID={_quote(str(account['access_key_id']))}",
            f"AWS_SECRET_ACCESS_KEY={_quote(str(account['secret_access_key']))}",
            f"AWS_DEFAULT_REGION={DEFAULT_REGION}",
            f"AWS_REGION={DEFAULT_REGION}",
        ]
        if account.get("session_token"):
            lines.append(f"AWS_SESSION_TOKEN={_quote(str(account['session_token']))}")
        env_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        # Windmill workers run on Linux and the credential loader rejects files
        # that are readable by group or other users.
        os.chmod(env_file, 0o600)
        entries.append({
            "name": str(account.get("name") or account_id),
            "account_id": account_id,
            "env_file": str(env_file),
        })
    manifest = directory / "accounts.yaml"
    manifest.write_text(yaml.safe_dump({"accounts": entries}, sort_keys=False), encoding="utf-8")
    return manifest


def _run_git(command: list[str], cwd: Path, environment: dict[str, str], secret: str) -> str:
    """Run Git without exposing the GitLab token in errors or command output."""
    completed = subprocess.run(command, cwd=cwd, env=environment, capture_output=True, text=True, check=False)
    if completed.returncode:
        details = (completed.stderr or completed.stdout or "").replace(secret, "[REDACTED]")
        raise RuntimeError(f"Git command failed ({completed.returncode}): {details[-2000:]}")
    return completed.stdout.strip()


def _publish_to_gitlab(
    artifacts: list[Path], account_id: str, runtime: Path, repository_url: str
) -> dict[str, Any]:
    """Commit the generated report artifacts into the account-specific folder."""
    token = _windmill_variable(GITLAB_TOKEN_VARIABLE)
    if not token:
        raise RuntimeError(f"Windmill variable {GITLAB_TOKEN_VARIABLE} is empty")

    # GIT_ASKPASS keeps the token out of the repository URL and process
    # arguments. The helper itself contains no secret; Git reads the token from
    # its environment only when authentication prompts occur.
    askpass = runtime / "git-askpass.sh"
    askpass.write_text(
        "#!/bin/sh\n"
        "case \"$1\" in\n"
        "  *Username*) printf '%s\\n' oauth2 ;;\n"
        "  *) printf '%s\\n' \"$GITLAB_PUSH_TOKEN\" ;;\n"
        "esac\n",
        encoding="utf-8",
    )
    os.chmod(askpass, 0o700)
    environment = os.environ.copy()
    environment.update({
        "GIT_ASKPASS": str(askpass),
        "GITLAB_PUSH_TOKEN": token,
        "GIT_TERMINAL_PROMPT": "0",
    })

    checkout = runtime / "aws-inventory-scan"
    _run_git(["git", "clone", "--depth", "1", repository_url, str(checkout)], runtime, environment, token)
    report_directory = checkout / f"{account_id}-reports"
    report_directory.mkdir(parents=True, exist_ok=True)
    published = []
    for artifact in artifacts:
        destination = report_directory / artifact.name
        shutil.copy2(artifact, destination)
        published.append(destination.name)

    _run_git(["git", "config", "user.name", "Windmill AWS Inventory"], checkout, environment, token)
    _run_git(["git", "config", "user.email", "windmill-aws-inventory@users.noreply.gitlab.com"], checkout, environment, token)
    _run_git(["git", "add", "--", f"{account_id}-reports"], checkout, environment, token)
    staged = subprocess.run(["git", "diff", "--cached", "--quiet", "--exit-code"], cwd=checkout,
                            env=environment, capture_output=True, text=True, check=False)
    if staged.returncode == 0:
        print(f"GitLab report files are unchanged in {account_id}-reports; nothing to commit")
        return {"status": "unchanged", "directory": f"{account_id}-reports", "files": published}
    commit_message = f"Add AWS inventory report for {account_id}"
    _run_git(["git", "commit", "-m", commit_message], checkout, environment, token)
    commit = _run_git(["git", "rev-parse", "HEAD"], checkout, environment, token)
    _run_git(["git", "push", "origin", "HEAD"], checkout, environment, token)
    print(f"Pushed GitLab report commit {commit[:12]} to {account_id}-reports")
    return {"status": "pushed", "directory": f"{account_id}-reports", "files": published, "commit": commit}


def main(
    accounts: str,
) -> dict[str, Any]:
    """Run the fixed full scan using comma-separated account IDs."""
    account_ids = _parse_account_ids(accounts)
    resolved_accounts = _credentials_from_variable(account_ids)
    with tempfile.TemporaryDirectory(prefix="aws-ri-windmill-") as runtime_name:
        runtime = Path(runtime_name)
        modules = _clone_modules(DEFAULT_REPOSITORY_URL, SOURCE_REF, runtime)
        if str(modules) not in sys.path:
            sys.path.insert(0, str(modules))
        from aws_ri.cli.main import cli

        work = runtime / "work"
        work.mkdir()
        accounts_file = _write_credentials(resolved_accounts, work)
        output = work / f"{OUTPUT_PREFIX}.xlsx"
        args = [
            "generate-multi", "--accounts-file", str(accounts_file),
            "--out", str(output), "--days", str(SCAN_DAYS),
        ]
        try:
            cli.main(args=args, standalone_mode=False)
        except Exception as error:
            raise RuntimeError(f"Inventory scan failed: {error}") from error
        artifacts = [output]
        drawio = output.with_suffix(".drawio")
        if drawio.exists():
            artifacts.append(drawio)
        excel_size = _file_size(output)
        print(f"AWS inventory Excel report: {output} ({excel_size['size_bytes']:,} bytes; {excel_size['size']})")
        response: dict[str, Any] = {
            "status": "completed",
            "accounts": account_ids,
            "days": SCAN_DAYS,
            "regions": "all enabled regions",
            "artifacts": [str(path) for path in artifacts],
            "excel_file": {"path": str(output), **excel_size},
        }
        try:
            repository_url = _windmill_variable(GITLAB_REPOSITORY_VARIABLE)
            response["gitlab"] = {
                "repository": repository_url.removesuffix(".git"),
                **_publish_to_gitlab(artifacts, account_ids[0], runtime, repository_url),
            }
        except Exception as error:
            raise RuntimeError(f"Inventory artifacts were created, but GitLab publishing failed: {error}") from error
        if S3_BUCKET:
            client = boto3.client("s3")
            prefix = S3_PREFIX.strip("/")
            uploaded = []
            for artifact in artifacts:
                key = f"{prefix}/{artifact.name}" if prefix else artifact.name
                client.upload_file(str(artifact), S3_BUCKET, key)
                uploaded.append({"bucket": S3_BUCKET, "key": key, "s3_uri": f"s3://{S3_BUCKET}/{key}"})
            response["uploaded_artifacts"] = uploaded
        return json.loads(json.dumps(response, default=str))
