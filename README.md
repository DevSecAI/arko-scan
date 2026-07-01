# Arko Scan (GitHub Action)

Runs a full Arko security build scan against the checked-out source on every
push or pull request. The action zips the checkout, uploads it to Arko,
waits for the scan to finish, then:

- annotates findings on the code (`::error` for critical/high, `::warning`
  for medium/low, with file and line where available),
- writes a step summary with a verdict, severity counts, the top findings
  and their suggested fixes, and a link to the full report in the Arko
  console,
- sets outputs you can use in later steps.

## Advisory by default

Arko advises — it never blocks a merge unless you opt in. With the default
`fail-on: ''` the step always exits 0, whatever the scan finds. Set
`fail-on: critical`, `high`, or `medium` to fail the step when findings at
or above that severity exist.

The one exception: if the scan itself cannot run or finish (bad token,
upload failure, timeout), the step fails so a broken scan is never silently
green. Add `continue-on-error: true` to the step if you would rather
swallow those too.

## Usage

Create an API token in the Arko console under **Admin → API Access** and
store it as a repository secret named `ARKO_API_TOKEN`.

```yaml
name: arko-scan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    timeout-minutes: 25
    steps:
      - uses: actions/checkout@v4

      - name: Arko Scan
        uses: ./.github/actions/arko-scan
        with:
          api-token: ${{ secrets.ARKO_API_TOKEN }}
          # Optional: gate merges on high-or-worse findings.
          # fail-on: high
```

The snippet above assumes the `arko-scan` action folder has been copied
into your repository at `.github/actions/arko-scan` (three files:
`action.yml`, `scan.sh`, this README). Once the action is published to a
public repository you can reference it directly with
`uses: <owner>/<repo>/.github/actions/arko-scan@<ref>` instead.

## Inputs

| Input | Default | Description |
|---|---|---|
| `api-token` | — | Arko API token, sent as `X-Arko-Token`. From **Admin → API Access**; store as a secret. Preferred. |
| `bearer-token` | — | Alternative: a JWT sent as `Authorization: Bearer`. `api-token` wins when both are set. |
| `api-base` | `https://arko.devsecai.io` | Arko API base URL. |
| `project-name` | repository name | Project name shown in the Arko console. |
| `branch` | current ref name | Branch recorded on the scan (PR head branch on `pull_request`). |
| `fail-on` | `''` (advisory) | `critical` \| `high` \| `medium` — exit 1 when findings at/above that severity exist. Empty = never fail on findings. |
| `max-wait-seconds` | `1200` | How long to wait for the scan before timing out. |
| `exclude` | — | Extra zip exclusions, newline-separated (`zip -x` syntax). `.git`, `node_modules`, `dist`, `build`, `.venv` and `*.zip` are always excluded. |

## Outputs

| Output | Description |
|---|---|
| `scan-id` | The Arko scan id (also links the console report). |
| `verdict` | `passing` \| `advisory` \| `failing` \| `error`. |
| `critical-count` | Critical findings on this scan. |
| `high-count` | High findings on this scan. |
| `medium-count` | Medium findings on this scan. |
| `low-count` | Low findings on this scan. |

## Troubleshooting

- **401/403 on upload-url or start** — the token is missing, wrong, or the
  organisation is not enabled for Build Scan. Re-create the token under
  **Admin → API Access** and check the `ARKO_API_TOKEN` secret. New
  organisations need Build Scan switched on by an Arko admin.
- **403 on the S3 upload** — the presigned PUT signs the exact
  `Content-Length` and the `x-amz-server-side-encryption: AES256` header;
  any mismatch breaks the signature. The URL also expires — re-run the job.
- **409 on start** — the scan was not awaiting upload (already started, or
  the slot expired). Re-run the job to create a fresh scan.
- **412 on start** — the uploaded archive was not found in S3; the upload
  failed or hit an expired URL. Re-run the job.
- **Timeout** — archives over ~50 MB or ~500 files can spend 60–120s in
  cold provisioning before the first phase starts, and the server fails
  scans with no heartbeat at ~20 minutes. Trim the archive with `exclude`
  patterns, or raise `max-wait-seconds` (the run prints the scan id and a
  console link so you can check whether it finished anyway).
- **Findings table says the breakdown could not be fetched** — the scan
  finished; the findings list request failed (very large result sets can
  exceed the load balancer's 1 MB response cap). Open the console link for
  the full report.
