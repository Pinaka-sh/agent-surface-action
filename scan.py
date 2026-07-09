#!/usr/bin/env python3
"""
Pinaka Agent-Surface Scan — GitHub Action runner (scan-in-CI).

Runs the stdlib-only `agent_discovery` engine inside the customer's own CI, then
POSTs only the *redacted* graph to Pinaka. The customer's source code never leaves
their runner and Pinaka never holds a GitHub token — the API key lives in their
repo secrets, the PR comment uses the workflow's own GITHUB_TOKEN.

Zero third-party dependencies: discovery is AST/stdlib, the HTTP calls use urllib.
This is the same contract the local MCP `discover_agent_surface` tool uses
(discover -> redact -> POST /api/agents/discovery), just driven from CI and tagged
`source=github_action` so the backend auto-registers the connector.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

# The vendored engine sits next to this script.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import agent_discovery as ad  # noqa: E402

_SEV_RANK = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# The engine emits HIGH/MEDIUM/LOW; map onto the fail-on scale.
_FINDING_SEV = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def _env(name: str, default: str = "") -> str:
    return (os.getenv(name) or default).strip()


def _post_json(url: str, payload: dict, headers: dict, timeout: int = 30) -> dict:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read().decode()
    return json.loads(body) if body else {}


def _upload(api_url: str, api_key: str, project: str, graph: dict, repo: str) -> dict:
    url = api_url.rstrip("/") + "/api/agents/discovery"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "pinaka-agent-surface-action",
    }
    payload = {
        "project": project,
        "graph": graph,
        "source": "github_action",
        "repo": repo,
    }
    return _post_json(url, payload, headers)


def _maybe_comment_on_pr(summary: str) -> None:
    """Best-effort PR comment using the workflow's GITHUB_TOKEN. Needs the calling
    workflow to grant `pull-requests: write`. Pinaka is not involved in this call."""
    token = _env("GITHUB_TOKEN")
    repo = _env("GITHUB_REPOSITORY")
    event_path = _env("GITHUB_EVENT_PATH")
    if not (token and repo and event_path and os.path.exists(event_path)):
        return
    try:
        with open(event_path) as f:
            event = json.load(f)
        pr = event.get("pull_request", {}).get("number") or event.get("number")
        if not pr:
            return  # not a PR event
        url = f"https://api.github.com/repos/{repo}/issues/{pr}/comments"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "User-Agent": "pinaka-agent-surface-action",
        }
        body = "## 🛡️ Pinaka Agent Surface\n\n" + summary
        _post_json(url, {"body": body[:65000]}, headers)
        print("Posted PR comment.")
    except Exception as e:  # noqa: BLE001 - PR comment is best-effort
        print(f"::warning::Could not post PR comment: {e}")


def _should_upload(explicit: str, event: str) -> bool:
    """Whether to write a snapshot to the Pinaka dashboard.

    Posture and drift track the CANONICAL surface — what is merged on the default
    branch — so a `pull_request` run stays advisory (scan + comment + gate) and does
    NOT upload, or experimental PR states would pollute the posture history. Every
    other event (push, workflow_dispatch, schedule, or a local run with no event)
    is canonical and uploads. An explicit `PINAKA_UPLOAD` (true/false) overrides."""
    if explicit:
        return explicit.lower() in ("1", "true", "yes", "on")
    return event.lower() not in ("pull_request", "pull_request_target")


def _fail_gate(findings: list, fail_on: str) -> int:
    threshold = _SEV_RANK.get(fail_on.lower(), 0)
    if threshold == 0:
        return 0
    worst = max((_FINDING_SEV.get(str(f.get("severity")).upper(), 0) for f in findings),
                default=0)
    if worst >= threshold:
        print(f"::error::Findings at or above '{fail_on}' present "
              f"(worst severity rank {worst} >= {threshold}).")
        return 1
    return 0


def main() -> int:
    api_key = _env("PINAKA_API_KEY")
    if not api_key:
        print("::error::PINAKA_API_KEY is not set. Add your pk_live_ key as a repo "
              "secret and expose it to this step as the PINAKA_API_KEY env var.")
        return 1

    scan_path = _env("PINAKA_SCAN_PATH", ".")
    api_url = _env("PINAKA_API_URL", "https://api.pinaka.sh")
    repo = _env("GITHUB_REPOSITORY")
    project = _env("PINAKA_PROJECT") or repo or Path(scan_path).resolve().name
    fail_on = _env("PINAKA_FAIL_ON", "none")
    comment = _env("PINAKA_COMMENT_ON_PR", "true").lower() in ("1", "true", "yes", "on")
    should_upload = _should_upload(_env("PINAKA_UPLOAD"), _env("GITHUB_EVENT_NAME"))

    # 1. Discover (local, AST) + human summary.
    result = ad.discover(scan_path)
    summary = ad.format_summary(result)
    print(summary)

    # 2. Redact (strip secrets) and upload only the graph — but ONLY for the
    # canonical surface. Posture/drift track the default branch (what is actually
    # merged), so a pull_request run is advisory: it scans, comments, and gates,
    # but never writes a snapshot, keeping experimental PR states out of the
    # posture history. See _should_upload; PINAKA_UPLOAD overrides.
    if should_upload:
        redacted = ad.redact(result)
        try:
            resp = _upload(api_url, api_key, project, redacted, repo)
            print(f"\n✅ Uploaded to Pinaka as project '{project}' "
                  f"(discovery {resp.get('discovery_id', '?')}).")
        except urllib.error.HTTPError as e:
            detail = e.read().decode()[:300] if hasattr(e, "read") else ""
            print(f"::error::Upload failed: HTTP {e.code} {detail}")
            return 1
        except Exception as e:  # noqa: BLE001
            print(f"::error::Upload failed: {e}")
            return 1
    else:
        print("\nℹ️  Advisory run (pull_request): findings are commented on the PR "
              "and gated, but not uploaded to the Pinaka dashboard. Posture tracks "
              "the default branch.")

    # 3. Optional PR comment (uses GITHUB_TOKEN, not Pinaka).
    if comment:
        _maybe_comment_on_pr(summary)

    # 4. Optional severity gate.
    return _fail_gate(result.get("findings", []), fail_on)


if __name__ == "__main__":
    sys.exit(main())
