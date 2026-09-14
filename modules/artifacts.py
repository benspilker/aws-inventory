"""Artifact upload helpers for Windmill jobs."""

from __future__ import annotations

from pathlib import Path

import boto3


def upload_artifacts(
    artifacts: list[Path], bucket: str, prefix: str
) -> list[dict[str, str]]:
    """Upload generated report files to S3 and return stable artifact metadata."""
    if not bucket.strip():
        raise ValueError("s3 bucket must not be empty")
    client = boto3.client("s3")
    uploaded: list[dict[str, str]] = []
    clean_prefix = prefix.strip("/")
    for artifact in artifacts:
        if not artifact.exists() or not artifact.is_file():
            raise FileNotFoundError(str(artifact))
        key = f"{clean_prefix}/{artifact.name}" if clean_prefix else artifact.name
        client.upload_file(str(artifact), bucket, key)
        uploaded.append({"bucket": bucket, "key": key, "s3_uri": f"s3://{bucket}/{key}"})
    return uploaded
