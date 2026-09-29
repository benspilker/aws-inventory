# Windmill integration

This repository contains the AWS inventory application and its Windmill
entry points. The canonical report implementation is in `modules/aws_ri`;
both entry points ultimately use the same report writer.

## Draw.io resource map

Each generated Excel report with inventory now includes an adjacent `.drawio`
resource map. Its first tab is an account-wide VPC index. Each VPC has a detail
tab with resources grouped inside subnet and VPC boundaries, followed by an
account/regional services tab and a tabular `Associations` index. VPC and subnet
membership is represented by containment so those common links do not create
crossing connector lines. Other resource relationships remain listed in the
association index.

Resource cards prefer the AWS `Name` tag, then the inventory resource name,
with the resource ID shown as a secondary label. The existing Network, Compute,
Data, Security, and Other color palette is retained. The map uses names, tags,
regions, and configuration already collected into the inventory report; it
does not make additional AWS API calls.

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

## Worker setup and source changes

`aws_inventory_windmill.py` clones this repository's configured branch into a
temporary worker directory and loads `modules/aws_ri` from that checkout.
Changes to the Draw.io layout therefore belong in
`modules/aws_ri/infrastructure/excel/drawio_graph_writer.py`; report assembly
and relationship extraction are in `modules/aws_ri/infrastructure/excel/excel_writer.py`.
No generated Windmill copy of the report writer needs rebuilding.

`aws_inventory_main.py` uses the local repository package. The shared runtime
helper supports either `modules/aws_ri` or `src/aws_ri` layouts and places the
matching source directory on `PYTHONPATH` for the CLI subprocess.

The Windmill worker needs the third-party packages in `requirements.txt` and
the access configured for the selected entry point. For production, prefer an
IAM role on the worker that can assume read-only roles in target accounts.
Temporary access keys are supported for compatibility, but their expiration
must be handled by the calling flow.
