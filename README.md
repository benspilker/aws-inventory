# Windmill integration

This folder provides a Windmill deployment pair. The canonical entry file is
`aws_inventory_windmill.py`; it is intentionally slim and loads the full
application from the sibling `modules/aws_ri` package at runtime.

The `modules/aws_ri` package originated from the [AWS Resource Inventory
repository](https://github.com/hpfpv/aws-resource-inventory). The Windmill
deployment may use a separately managed module mirror or runtime checkout,
but that repository is the original source location for the application
modules.

## Entry point

Deploy `aws_inventory_windmill.py` as a Windmill Python script. Its `main`
function exposes one input named `accounts`, which should be a text value such
as:

```text
123456789012
```

All other scan settings are constants in the script: source repository URL,
`main` branch, 30-day cost window, all enabled regions, full (non-Lite)
collection, and inventory/cost/posture enabled. The AWS credentials are read
from the Windmill variable `u/bspilker/aws-temp-keys`.

The script retrieves the base64-encoded AWS export block from that Windmill
variable, decodes it in memory, and verifies the credentials' account with STS.
The variable's credentials must match the account ID entered in the textbox.

The Windmill script invokes the tested `generate-multi` workflow from the cloned source, writes the
XLSX and draw.io artifacts in the worker's temporary directory, and removes the
temporary credential files when the job ends. It also clones the GitLab report
repository and commits the artifacts into `<first-account-id>-reports`, using
the token stored in `u/bspilker/aws-inventory-scan-gitlab`. The GitLab
repository URL is read from the Windmill variable
`u/bspilker/aws-inventory-scan-gitlab-repository-url`. Set `s3_bucket` to upload the
artifacts to S3 as well. The GitLab token is never included in the repository
URL, command arguments, logs, or returned result.

## Worker setup

Windmill should sync the `windmill/modules` directory from GitLab and deploy
the entry script with that directory available beside it. The worker does not
need the repository's `src` package. It only needs the third-party packages in
`requirements.txt`. For production, prefer
an IAM role on the Windmill worker that can assume read-only roles in target
accounts. Temporary access keys are supported for compatibility, but their
expiration must be handled by the calling flow.

## Rebuilding the Windmill script

When the application source changes, update `modules/aws_ri` and run this from
the repository root:

```powershell
python windmill\build_windmill.py
```

That regenerates `aws_inventory_windmill.py` from the slim template. The
builder is development-time tooling; Windmill deployment needs the generated
entry script plus the `modules` directory.
