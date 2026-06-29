# Pinaka Agent Surface Scan — GitHub Action

Map your **AI-agent / MCP attack surface** on every push. The scan runs **inside your
own CI** — your source never leaves the runner, only a secrets-redacted graph is
uploaded, and **Pinaka never holds a GitHub token**.

It finds the MCP servers and agent tools in your code, what each tool can reach, the
external hosts it references, hidden instructions in tool descriptions, injectable
sinks (command / SQL / path / SSTI / deserialization / config-to-command), and the
Claude Skills (`SKILL.md`) in your repo — mapped to OWASP MCP/LLM/ASI and MITRE ATLAS.

## Why this is safe (and cheap)

- **Scan-in-place.** Discovery is a stdlib-only AST pass that runs on your runner. We
  upload only the redacted graph (tools, frameworks, external hosts, findings).
- **No credential custody.** Your `pk_live_` key lives in *your* repo secrets. The PR
  comment uses the workflow's own `GITHUB_TOKEN`. Pinaka stores neither.
- **No vendor compute.** The heavy lifting is your CI minutes, not our servers.

## Usage

1. Create a Pinaka API key (Dashboard → Settings → **API Keys**) and add it as a repo
   secret named `PINAKA_API_KEY`.
2. Add a workflow:

```yaml
# .github/workflows/pinaka-agent-surface.yml
name: Pinaka Agent Surface
on:
  push:
    branches: [main]
  pull_request:

permissions:
  contents: read
  pull-requests: write   # only needed for the PR comment

jobs:
  agent-surface:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Pinaka-sh/agent-surface-action@v1
        with:
          api-key: ${{ secrets.PINAKA_API_KEY }}
          # project: my-service        # defaults to owner/repo
          # path: .                     # subdir to scan (default: whole repo)
          # fail-on: high               # none|low|medium|high|critical
          # comment-on-pr: 'true'
```

3. Push. The repo appears in **Settings → Integrations**, and the mapped surface
   renders in the **Agent Surface** view. Enable the cross-surface bridge there to
   correlate agent deploy hosts against your monitored subdomains.

## Inputs

| Input | Default | Description |
|---|---|---|
| `api-key` | *(required)* | Pinaka API key (`pk_live_...`), from a repo secret. |
| `project` | `owner/repo` | Project identifier shown in Pinaka. |
| `path` | `.` | Path within the repo to scan. |
| `api-url` | `https://api.pinaka.sh` | Pinaka API base URL. |
| `fail-on` | `none` | Fail the job if a finding of this severity or higher exists. |
| `comment-on-pr` | `true` | Post a summary comment on the PR (needs `pull-requests: write`). |

## What gets uploaded

Only a **redacted graph**: tool names + descriptions (secrets stripped), capabilities,
external hostnames (your own infra, kept for the cross-surface bridge), and findings.
Your source code never leaves the runner.

## License

MIT — see [LICENSE](LICENSE).
