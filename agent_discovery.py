#!/usr/bin/env python3
"""
Agent-surface discovery — the "agent flavour" companion to Pinaka's EASM.

Static, stdlib-only parser that walks a repo and maps its AI-agent attack
surface: the MCP/agent framework, every exposed tool, what each tool can reach,
the external hosts referenced (bridge fuel for correlating against
resolved_subdomains), and a *small, high-signal* finding set.

Design constraints (see docs + tasks/todo.md "Dual-Surface" plan):
  - stdlib only (no new deps) so it runs edge-side on the user's machine
  - emits a redacted node/edge graph; raw hostnames are kept locally but a
    redacted() view is what crosses the wire to /api/agents/discovery
  - signal over volume: a few precise rules, not a 2,800-item firehose

Run standalone:
    python3 agent_discovery.py <path>
"""
from __future__ import annotations

import ast
import json
import re
import sys
from collections import defaultdict
from pathlib import Path
from typing import Any

# ---------------------------------------------------------------------------
# Detection tables
# ---------------------------------------------------------------------------

# Imperative / instruction-like language in a tool description is an injection
# surface (g0 AA-GI-017). Lower severity here than g0 rates it because Pinaka's
# descriptions are first-party, but still worth scrubbing the vector.
# All-caps emphatic directives — the injection-style signal. CASE-SENSITIVE on
# purpose: descriptive lowercase prose ("never returns null", "must be valid")
# must NOT trip it.
_IMPERATIVE_RE = re.compile(r"\b(ALWAYS|NEVER|MUST|DO NOT|DON'T|IMPORTANT)\b")
# Phrases addressed at the agent (any case) — genuinely instruction-like.
_DIRECTIVE_RE = re.compile(
    r"\byou (?:should|must)\b|\bmake sure\b|\bbe sure to\b|\bremember to\b|\bensure you\b",
    re.IGNORECASE,
)

# Capability sinks, mapped from the module/attribute root used inside a tool body.
_CAP_SINKS: dict[str, str] = {
    "subprocess": "exec",
    "os.system": "exec",
    "os.popen": "exec",
    "eval": "exec",
    "exec": "exec",
    "open": "filesystem",
    "pathlib": "filesystem",
    "shutil": "filesystem",
    "requests": "network",
    "httpx": "network",
    "urllib": "network",
    "socket": "network",
    "boto3": "cloud",
    "pymongo": "database",
}

# Tool categories that ultimately reach the backend API (proxy tools). Used to
# infer reach for tools whose client call is indirect, so Data Reach isn't blank.
_API_CATEGORIES = {"recon_read", "recon_write", "recon_trigger", "scan",
                   "analysis", "search", "pentest", "report"}

# Tool-poisoning / hidden-instruction markers in a description (OWASP MCP03).
# Only explicit injection markers — bare file-path mentions (.env, ~/.ssh) were
# removed: tools legitimately document those paths, so they false-positive.
# The `system:` role-label marker is anchored to a LINE START (`(?:^|\n)`): a fake
# system prompt lives at the start of a line, whereas the bare token "system:"
# matches benign mid-word/mid-line text — a tool param `include_system:`, a path
# `FileSystem:`, or prose "operating system:" — which is a real false positive
# (caught on public MCP-server tool descriptions). The other markers are explicit
# enough to stay unanchored.
_POISON_RE = re.compile(
    r"<\s*important\s*>|<!--|<\s*s\s*>|ignore\s+(previous|prior|above|all)|"
    r"do not\s+(tell|inform|mention|reveal|disclose)|disregard\b|(?:^|\n)\s*system\s*:",
    re.IGNORECASE,
)
# AS-GI-003: invisible / control characters in a tool description have no
# legitimate purpose and are the carrier for hidden-instruction smuggling a human
# reviewer can't see but the model reads: zero-width joiners, bidi overrides
# (Trojan Source), the Unicode Tags block (ASCII smuggling), and ANSI terminal
# escapes. Printable prose, accents, emoji and CJK all pass, so it is zero-FP.
# LRM/RLM and soft-hyphen are intentionally excluded: they appear in legitimate
# RTL / hyphenated text and would false-positive.
# Codepoints listed explicitly as ASCII escapes (never inlined as literal
# invisibles) so the rule stays reviewable and the source file is clean ASCII.
_HIDDEN_CODEPOINTS = (
    "\u200b\u200c\u200d"        # zero-width space / non-joiner / joiner
    "\u2060\u2061\u2062\u2063\u2064"  # word joiner + invisible math operators
    "\u202a\u202b\u202c\u202d\u202e"  # bidi embedding / override (Trojan Source)
    "\u2066\u2067\u2068\u2069"  # bidi isolates
    "\ufeff"                      # zero-width no-break space / BOM
    "\x1b"                        # ESC (ANSI terminal escape)
)
_HIDDEN_RE = re.compile(
    "[" + _HIDDEN_CODEPOINTS + "]"
    "|[\U000e0000-\U000e007f]"   # Unicode Tags block (ASCII tag smuggling)
)
# Action-class signals from the tool name (agency / data-egress classification).
_DESTRUCTIVE_RE = re.compile(r"^(delete|drop|remove|destroy|purge|wipe|revoke)_", re.IGNORECASE)
# External-send / data-egress tool names. `send_` is constrained to an explicit
# external channel (send_email/_sms/_webhook…) or a `send_to_` destination so
# internal sinks (send_status_to_ui, send_response) don't false-positive.
_EXTERNAL_SEND_RE = re.compile(
    r"^(?:report_to|submit_to|post_to|push_to|export_to|send_to)_"
    r"|^send_(?:email|sms|mms|mail|message|msg|webhook|notification|notif|slack|telegram|discord|fax|text)"
    r"|^(?:publish|notify)_",
    re.IGNORECASE,
)
_STATE_CHANGE_RE = re.compile(r"^(create|update|set|trigger|enrich|store|add|register|start)_", re.IGNORECASE)
_CRED_RE = re.compile(r"auth_context|credential|set_cookie|store_token", re.IGNORECASE)
_SENS_READ_RE = re.compile(r"secret|credential|password|cookie|api[_-]?key", re.IGNORECASE)

# Each rule -> the security standards it maps to (credibility + triage).
# ATLAS-* = MITRE ATLAS technique IDs, verified against ATLAS v6.0.0 (2026-05-27,
# atlas.mitre.org). Mapped only where a technique genuinely applies; AS-TR-001
# (transport/DNS-rebinding) has no clean ATLAS technique and stays OWASP-only.
# The taint-to-sink rules map to AML.T0053 (AI Agent Tool Invocation — a tool
# invocation reaching code/data/network), and the code-exec ones additionally to
# AML.T0050 (Command and Scripting Interpreter).
_STANDARDS: dict[str, list[str]] = {
    "AS-GI-001": ["OWASP-MCP03", "OWASP-LLM01", "ATLAS-AML.T0110"],
    "AS-GI-002": ["OWASP-MCP03", "OWASP-LLM01", "OWASP-ASI01", "ATLAS-AML.T0051.001", "ATLAS-AML.T0110"],
    "AS-GI-003": ["OWASP-MCP03", "OWASP-LLM01", "OWASP-ASI01", "ATLAS-AML.T0068", "ATLAS-AML.T0110"],
    "AS-TS-001": ["OWASP-MCP05", "OWASP-LLM05", "ATLAS-AML.T0050", "ATLAS-AML.T0053"],
    "AS-TS-002": ["OWASP-MCP05", "ATLAS-AML.T0053"],
    "AS-TS-003": ["OWASP-MCP05", "OWASP-LLM05", "ATLAS-AML.T0053"],
    "AS-TS-004": ["OWASP-MCP05", "OWASP-LLM05", "ATLAS-AML.T0050", "ATLAS-AML.T0053"],
    "AS-TS-005": ["OWASP-MCP05", "OWASP-LLM05", "ATLAS-AML.T0053"],
    "AS-TS-006": ["OWASP-MCP05", "OWASP-LLM05", "ATLAS-AML.T0053"],
    "AS-TS-007": ["OWASP-MCP05", "OWASP-LLM05", "ATLAS-AML.T0050", "ATLAS-AML.T0053"],
    "AS-TS-008": ["OWASP-MCP05", "OWASP-LLM05", "ATLAS-AML.T0050", "ATLAS-AML.T0053"],
    "AS-TS-009": ["OWASP-MCP05", "OWASP-MCP04", "ATLAS-AML.T0050", "ATLAS-AML.T0053"],
    "AS-EA-001": ["OWASP-MCP02", "OWASP-LLM06", "OWASP-ASI02", "ATLAS-AML.T0053", "ATLAS-AML.T0101"],
    "AS-IA-001": ["OWASP-MCP01", "OWASP-MCP07", "ATLAS-AML.T0083"],
    "AS-DL-001": ["OWASP-MCP10", "OWASP-LLM02", "ATLAS-AML.T0086"],
    "AS-SE-001": ["OWASP-MCP01", "OWASP-LLM02", "ATLAS-AML.T0055", "ATLAS-AML.T0083"],
    "AS-TR-001": ["OWASP-MCP07"],
}

_FRAMEWORK_IMPORTS: dict[str, str] = {
    "mcp.server.fastmcp": "mcp",
    "fastmcp": "mcp",
    "langchain": "langchain",
    "langgraph": "langgraph",
    "crewai": "crewai",
    "autogen": "autogen",
    "llama_index": "llama_index",
}

_URL_RE = re.compile(r"https?://([a-zA-Z0-9][a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})")
_SECRET_RE = re.compile(
    r"(?:Bearer\s+[A-Za-z0-9._\-]{12,}|pk_live_[A-Za-z0-9]{12,}|"
    r"sk_live_[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16}|sk-[A-Za-z0-9]{20,}|"
    r"gh[opusr]_[A-Za-z0-9]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|"
    r"AIza[0-9A-Za-z_\-]{35}|-----BEGIN[A-Z ]*PRIVATE KEY-----)"
)
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "__pycache__", "dist",
              "build", ".next", "coverage", "site-packages", "dist-packages",
              ".tox", ".eggs", ".mypy_cache", ".pytest_cache", "vendor", ".gradle",
              "bower_components", ".terraform"}


def _vendored(p: Path) -> bool:
    """True for installed-dependency / build / virtualenv paths — their URLs and
    'tools' are not the user's agent code (e.g. psutil/pydantic in a venv)."""
    return any(
        part in _SKIP_DIRS or part.endswith("venv") or part.endswith("-env")
        for part in p.parts
    )

# Host source-confidence classification. A host found in deploy/infra config is
# a strong "this agent runs here" signal (bridge candidate); one found in a
# test/probe/payload file is noise; reserved/example domains are always dropped.
_CONF_RANK = {"high": 3, "medium": 2, "low": 1}

# Reserved / non-routable / placeholder hosts — never bridge candidates.
_RESERVED_HOST_RE = re.compile(
    r"(?:^|\.)(?:example\.(?:com|org|net)|test|local|localhost|invalid|"
    r"internal|arpa|lan)$",
    re.IGNORECASE,
)
# Files whose hosts are test data / security payloads / exploit fixtures.
_TEST_SOURCE_RE = re.compile(
    r"(?:^|/)(?:tests?|fixtures?|mocks?|examples?|payloads?|wordlists?|seeds?)(?:/|$)"
    r"|(?:test_|_test\.|\.test\.|\.spec\.|probe_|jwt_bypass|exploit|payload|sample|seed)",
    re.IGNORECASE,
)
# Deploy/infra config file names — hosts here say where the service runs.
_DEPLOY_NAMES = {"dockerfile", "procfile", ".mcp.json", "vercel.json",
                 "netlify.toml", "serverless.yml", "serverless.yaml", "fly.toml",
                 "app.json"}


def _classify_source(rel: str) -> tuple[str, str]:
    """(confidence, kind) for hosts found in this file path."""
    low = rel.lower()
    name = low.rsplit("/", 1)[-1]
    if _TEST_SOURCE_RE.search(low):
        return ("low", "test")
    if (low.endswith(".tf") or name in _DEPLOY_NAMES
            or "/.github/workflows/" in low or name.startswith(".env")
            or "/infrastructure/" in low
            or ((low.endswith(".yaml") or low.endswith(".yml"))
                and any(k in low for k in ("ingress", "deploy", "service", "k8s", "helm")))):
        return ("high", "deploy")
    return ("medium", "integration")


def _is_reserved_host(h: str) -> bool:
    # reserved/example domains, bare IPv4, or any IPv6 literal (contains ':')
    return bool(_RESERVED_HOST_RE.search(h)) or h.replace(".", "").isdigit() or ":" in h


def _collect_hosts(text: str, rel: str, hosts: dict[str, dict]) -> None:
    """Extract + classify hosts from one file, keeping the best source seen."""
    conf, kind = _classify_source(rel)
    for h in _URL_RE.findall(_SECRET_RE.sub("<REDACTED>", text)):
        h = h.lower()
        if _is_reserved_host(h):
            continue
        cur = hosts.get(h)
        if cur is None or _CONF_RANK[conf] > _CONF_RANK[cur["confidence"]]:
            hosts[h] = {"confidence": conf, "kind": kind, "source": rel,
                        "count": (cur["count"] + 1) if cur else 1}
        else:
            cur["count"] += 1


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------

def _attr_chain(node: ast.AST) -> str:
    """Flatten an attribute/name expression to a dotted string (best effort)."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


def _is_mcp_tool_decorator(dec: ast.AST) -> bool:
    """Match @mcp.tool() and @mcp.tool."""
    target = dec.func if isinstance(dec, ast.Call) else dec
    return isinstance(target, ast.Attribute) and target.attr == "tool"


def _decorator_base_name(dec: ast.AST) -> str | None:
    """The bare name of a decorator: @tool -> 'tool', @tool() -> 'tool', @m.tool -> 'tool'."""
    target = dec.func if isinstance(dec, ast.Call) else dec
    if isinstance(target, ast.Attribute):
        return target.attr
    if isinstance(target, ast.Name):
        return target.id
    return None


def _tool_wrapper_names(tree) -> set:
    """Names of custom decorators that internally apply `mcp.tool()`. Some servers
    wrap registration in a conditional-enable decorator (`def tool(...): ... return
    mcp.tool()(func)`) and decorate tools with that wrapper (`@tool(...)`) instead of
    `@mcp.tool` directly, so the literal-decorator match misses every tool. We only
    treat a name as a tool decorator if its function body actually calls `*.tool`
    (precise: a stray `@tool` that does not register an MCP tool is not matched).
    The decorator_list is excluded so a normal `@mcp.tool` tool is not mistaken for a wrapper."""
    names = set()
    for n in ast.walk(tree):
        if not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        for stmt in n.body:
            if any(isinstance(c, ast.Call) and _is_mcp_tool_decorator(c) for c in ast.walk(stmt)):
                names.add(n.name)
                break
    return names


def _extract_category(func: ast.FunctionDef) -> str | None:
    """Pull category from @traceable(metadata={"category": "..."})."""
    for dec in func.decorator_list:
        if not isinstance(dec, ast.Call):
            continue
        target = dec.func
        if not (isinstance(target, ast.Attribute) and target.attr == "traceable") \
                and not (isinstance(target, ast.Name) and target.id == "traceable"):
            continue
        for kw in dec.keywords:
            if kw.arg == "metadata" and isinstance(kw.value, ast.Dict):
                for k, v in zip(kw.value.keys, kw.value.values):
                    if isinstance(k, ast.Constant) and k.value == "category" \
                            and isinstance(v, ast.Constant):
                        return str(v.value)
    return None


def _tool_capabilities(func: ast.FunctionDef) -> set[str]:
    """Scan a tool body for capability sinks. 'pinaka-api' = goes through the
    authed client; raw sinks (exec/filesystem/network) are flagged separately."""
    caps: set[str] = set()
    for node in ast.walk(func):
        # any reference to the authed API client (direct or assigned) = pinaka-api
        if isinstance(node, ast.Name) and node.id in ("client", "_get_client"):
            caps.add("pinaka-api")
        if isinstance(node, ast.Call):
            chain = _attr_chain(node.func)
            root = chain.split(".")[0]
            if root in ("client", "_get_client") or chain.startswith("client."):
                caps.add("pinaka-api")
            for needle, cap in _CAP_SINKS.items():
                # Dotted sinks (e.g. "os.system") must match the full chain —
                # matching by root would flag any os.* call (os.getenv, os.path)
                # as exec. Single-name sinks (subprocess, eval, open, …) match
                # by root so subprocess.run / open(...) are caught.
                if "." in needle:
                    if chain == needle:
                        caps.add(cap)
                elif root == needle:
                    caps.add(cap)
    return caps


def _tool_params(func: ast.FunctionDef) -> list[str]:
    return [a.arg for a in func.args.args if a.arg not in ("self", "cls")]


def _tool_validates(func: ast.FunctionDef) -> bool:
    """Does the tool body call a validator on its input?"""
    for n in ast.walk(func):
        if isinstance(n, ast.Call):
            chain = _attr_chain(n.func).lower()
            if "validate" in chain or "sanitize" in chain:
                return True
    return False


def _action_class(name: str) -> str:
    if _DESTRUCTIVE_RE.match(name):
        return "destructive"
    if _EXTERNAL_SEND_RE.match(name):
        return "external_send"
    if _CRED_RE.search(name):
        return "credential"
    if _STATE_CHANGE_RE.match(name):
        return "state_change"
    return "read"


def _hidden_char_finding(name: str, loc: str, doc: str) -> dict | None:
    """AS-GI-003: a non-rendering character in a tool description is an
    instruction-smuggling carrier. Returns a finding (or None) for either scan
    path. Printable prose / accents / emoji / CJK never trip it."""
    m = _HIDDEN_RE.search(doc or "")
    if not m:
        return None
    return {
        "rule": "AS-GI-003",
        "severity": "HIGH",
        "title": "Invisible/control characters in MCP tool description",
        "tool": name,
        "location": loc,
        "detail": f"Description carries a non-rendering character (U+{ord(m.group(0)):04X}) "
                  "— zero-width, bidi-override, Unicode-Tag or ANSI-escape text is the "
                  "carrier for hidden instructions the model reads but a human reviewer cannot see.",
        "fix": "Strip descriptions to printable text; reject tool definitions containing control/format characters.",
    }


# ---------------------------------------------------------------------------
# Claude Skill (SKILL.md) ingestion. A skill is a directory with a SKILL.md
# (YAML frontmatter name/description + markdown body) plus plain helper scripts
# (ordinary top-level functions, NOT @mcp.tool-decorated). The description rules
# run on the SKILL.md text; the bundled functions are taint-scanned like tools.
# The whole pass is gated on SKILL.md presence, so a repo without one never
# enters it and normal MCP servers / repos cannot start flagging undecorated
# helpers — precision by construction. No new rule IDs: the vuln classes are
# identical, only the carrier differs (captured by the skill/surface keys).
# ---------------------------------------------------------------------------

def _parse_frontmatter(text: str) -> tuple[dict[str, str], str]:
    """Split a leading `---` YAML frontmatter block from the markdown body.
    Stdlib-only: reads scalar `key: value` lines (enough for name/description),
    skips list/block/empty values. No fence -> ({}, full text)."""
    s = text.lstrip("\ufeff")  # strip a leading BOM if present
    if not s.startswith("---"):
        return {}, text
    lines = s.split("\n")
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        return {}, text
    meta: dict[str, str] = {}
    for ln in lines[1:end]:
        m = re.match(r"^([A-Za-z][\w-]*):\s*(.*)$", ln)
        if not m:
            continue
        val = m.group(2).strip()
        if val == "" or val[0] in "[{|>":
            continue  # skip list/block/empty — we only need scalars
        meta[m.group(1).lower()] = val.strip("'\"")
    return meta, "\n".join(lines[end + 1:])


def _skill_description_findings(skill: str, loc: str, doc: str) -> list[dict]:
    """Text rules on a Claude Skill, attributed to the skill. ONLY AS-GI-003
    (invisible / control characters) runs here. We deliberately do NOT run the
    imperative (AS-GI-001) or poison-marker (AS-GI-002) prose rules on skill
    text: a skill is, by design, a body of natural-language instructions to the
    agent, so phrases like "do not mention", "ignore previous", or "system:"
    (and "FileSystem:") are normal authorship, not poisoning — pattern-matching
    them produces false positives on real skills (proven on a 45-server corpus).
    Whether visible instructions are "malicious" is inherently ambiguous for a
    skill and is dynamic/LLM territory. Hidden characters, by contrast, have no
    legitimate use in any text, so AS-GI-003 stays zero-FP; the real injectable
    risk is in the bundled scripts, caught by the taint pass."""
    hu = _hidden_char_finding(skill, loc, doc)
    if hu:
        hu["title"] = "Invisible/control characters in a Claude Skill"
        hu["skill"] = skill
        hu["surface"] = "skill"
        return [hu]
    return []


def _skill_tool_functions(tree: ast.Module) -> list:
    """Module-level functions of a bundled skill script — the skill's 'tools'.
    Class/static-method bodies are intentionally not scanned: a behavioral flow
    spread across methods/files (e.g. an env-secret harvester reached only via a
    no-arg static method) is out of scope for intra-procedural taint, and
    scanning them would cost precision. Silence there is the boundary, not a miss."""
    return [n for n in tree.body
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _iter_skill_dirs(root: Path):
    """Yield each SKILL.md path under root (skipping vendored trees)."""
    for p in root.rglob("SKILL.md"):
        if _vendored(p):
            continue
        yield p


# ---------------------------------------------------------------------------
# Intra-procedural taint (AS-TS-004 command, 005 SQL, 006 path, 003 SSRF).
# Does a tool PARAMETER reach a dangerous sink unsanitized? Source-order walk so
# a sanitizer rebind (p = validate_path(p)) clears taint before the sink. Precision
# over recall: ambiguous / cross-function flows are missed, never guessed.
# ---------------------------------------------------------------------------

_CMD_DIRECT = ("os.system", "os.popen", "eval", "exec")
_PATH_SINKS = ("open", "os.open", "os.remove", "os.unlink", "os.rmdir",
               "shutil.copy", "shutil.copy2", "shutil.copyfile", "shutil.move",
               "shutil.rmtree", "shutil.copytree")
_NET_ROOTS = ("requests", "httpx", "urllib", "socket", "aiohttp")
# Deserialization sinks that execute arbitrary code on load (AS-TS-008). yaml.load
# is handled separately because a Safe loader makes it safe; safe_load never fires.
_DESER_SINKS = ("pickle.loads", "pickle.load", "cpickle.loads", "cpickle.load",
                "_pickle.loads", "_pickle.load", "marshal.loads", "marshal.load",
                "dill.loads", "dill.load")
# Calls that BUILD a tainted value from tainted args (vs. consume it -> sanitizer).
_TAINT_BUILDERS = ("str", "os.path.join", "os.path.dirname", "pathlib.path", "path")

_SINK_META = {
    "command": ("Tool parameter reaches a shell/eval sink (command injection)",
                "passes input into a process-exec or eval sink with no sanitization, so an agent steered into it gets code execution",
                "Pass args as a list without shell=True, or shlex.quote each value; never build a shell string from input."),
    "sql": ("Tool parameter reaches a SQL query string (SQL injection)",
            "formats input directly into the SQL string passed to execute()",
            "Use a parameterized query: execute(sql, (param,)). Never f-string / % / + input into SQL."),
    "path": ("Tool parameter reaches a filesystem path (path traversal)",
             "uses input as a file path with no containment check, so `../` escapes the intended directory",
             "Resolve under a fixed base and reject paths that escape it (basename, or realpath + prefix check)."),
    "network": ("Tool input reaches a network sink without validation",
                "passes input into a network request with no allow-list (SSRF)",
                "Allow-list hosts and schemes before the request."),
    "ssti": ("Tool parameter is rendered as a server-side template (template injection)",
             "builds a template from input and renders it, so an agent steered into it reaches code execution through the template engine",
             "Render a fixed template file and pass input as data; never build a template from input (avoid render_template_string / Environment.from_string on user input)."),
    "deser": ("Tool parameter is deserialized by an unsafe loader (insecure deserialization)",
              "loads input through pickle / yaml.load / marshal, which can execute arbitrary code while deserializing",
              "Use a safe format such as JSON, or yaml.safe_load; never unpickle data an agent can influence."),
    "config_exec": ("MCP server config command reaches a shell sink (config-to-command RCE)",
                    "executes a `command`/`args` value taken from a server config or registry entry through a shell sink, so a poisoned config is remote code execution (the OX Security / Anthropic-by-design STDIO class)",
                    "Launch with an argv list and never shell=True; allow-list the executable; treat any externally-sourced server config as untrusted."),
}

# MCP-server-config keys whose value is an executable command. A value pulled from
# one of these reaching a SHELL sink (shell=True / os.system / eval) is the
# config-to-command RCE class (AS-TS-009). An argv-list launch is the safe, common
# pattern and must NOT fire.
_CONFIG_CMD_KEYS = ("command", "args", "argv", "cmd")


def _is_sanitizer(chain: str) -> bool:
    """A call that makes its argument safe for a sink (consumes taint)."""
    c = chain.lower()
    if any(k in c for k in ("validate", "sanitize", "escape", "secure_filename",
                            "hexdigest", "hashlib", "uuid")):
        return True
    return c.rsplit(".", 1)[-1] in ("quote", "basename", "realpath", "normpath")


def _expr_tainted(node, tainted: set) -> bool:
    """Best-effort: does this expression carry taint from a tainted name?"""
    if isinstance(node, ast.Name):
        return node.id in tainted
    if isinstance(node, ast.JoinedStr):  # f-string
        return any(_expr_tainted(v.value, tainted) for v in node.values
                   if isinstance(v, ast.FormattedValue))
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _expr_tainted(node.left, tainted) or _expr_tainted(node.right, tainted)
    if isinstance(node, ast.IfExp):
        return _expr_tainted(node.body, tainted) or _expr_tainted(node.orelse, tainted)
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return any(_expr_tainted(e, tainted) for e in node.elts)
    if isinstance(node, ast.Starred):
        return _expr_tainted(node.value, tainted)
    if isinstance(node, ast.Subscript):       # arguments["x"] / arguments[0]
        return _expr_tainted(node.value, tainted)
    if isinstance(node, ast.Call):
        chain = _attr_chain(node.func).lower()
        if _is_sanitizer(chain):
            return False
        # Match .format / .join by ATTRIBUTE NAME, not the dotted chain: a string
        # LITERAL receiver (`"SELECT {}".format(p)`, `",".join(parts)`) flattens to
        # a chain of just "format"/"join" with no leading name, so chain.endswith
        # would miss it. The receiver (func.value) is added as a source too.
        attr = node.func.attr if isinstance(node.func, ast.Attribute) else ""
        if attr in ("format", "join") or chain in _TAINT_BUILDERS:
            srcs = list(node.args)
            if isinstance(node.func, ast.Attribute):
                srcs.append(node.func.value)  # "sep".join / tmpl.format / Path-ish
            return any(_expr_tainted(a, tainted) for a in srcs)
        # dict access on a tainted mapping stays tainted: arguments.get("x")
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "pop", "setdefault"):
            return _expr_tainted(node.func.value, tainted)
        return False
    return False


def _is_formatted(node) -> bool:
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    return (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format")


def _validation_clears(test, tainted: set) -> set:
    """An `if <test>: raise/return` whose test validates a param makes it clean after.
    Require a Call/Compare so a bare `if name:` is not mistaken for validation."""
    if not any(isinstance(n, (ast.Call, ast.Compare)) for n in ast.walk(test)):
        return set()
    return {n.id for n in ast.walk(test) if isinstance(n, ast.Name) and n.id in tainted}


def _expr_is_config_cmd(node, cfg_tainted: set) -> bool:
    """Does this expression carry an MCP-server-config command/args value?

    True for a `cfg["command"]` / `cfg.get("args")` access on a config-shaped key,
    a name we already marked config-tainted, or an f-string / concat built from one.
    Used only at SHELL sinks, so it stays precise: an argv-list launch never reaches here.
    """
    if isinstance(node, ast.Name):
        return node.id in cfg_tainted
    if isinstance(node, ast.Subscript):              # cfg["command"]
        key = node.slice
        return (isinstance(key, ast.Constant) and isinstance(key.value, str)
                and key.value.lower() in _CONFIG_CMD_KEYS)
    if isinstance(node, ast.Call):                   # cfg.get("command") / cfg.pop("args")
        if isinstance(node.func, ast.Attribute) and node.func.attr in ("get", "pop"):
            return any(isinstance(a, ast.Constant) and isinstance(a.value, str)
                       and a.value.lower() in _CONFIG_CMD_KEYS for a in node.args)
        return False
    if isinstance(node, ast.JoinedStr):              # f"{cfg['command']} ..."
        return any(_expr_is_config_cmd(v.value, cfg_tainted) for v in node.values
                   if isinstance(v, ast.FormattedValue))
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
        return _expr_is_config_cmd(node.left, cfg_tainted) or _expr_is_config_cmd(node.right, cfg_tainted)
    return False


def _classify_sink(call, tainted: set, cfg_tainted: set = frozenset(),
                   fmt_tainted: set = frozenset()):
    """(rule, severity, kind) if a tainted arg reaches a dangerous sink, else None."""
    chain = _attr_chain(call.func)
    low = chain.lower()
    root = low.split(".")[0]
    if root in ("client", "_get_client", "self"):
        return None  # authed client / instance method, not a raw sink
    args = call.args
    kws = {k.arg: k.value for k in call.keywords if k.arg}
    tainted_args = any(_expr_tainted(a, tainted) for a in args)

    is_subproc = root == "subprocess"
    shell_true = isinstance(kws.get("shell"), ast.Constant) and kws["shell"].value is True
    # Always-shell sinks (os.system/os.popen/eval/exec, incl. aliased) fire on any
    # tainted arg. subprocess.* (including Popen) only injects with shell=True — an
    # argv list is safe, so it must NOT fire otherwise (was a `.popen` false positive).
    always_shell = (not is_subproc) and (
        low in _CMD_DIRECT or low in ("system", "popen", "eval", "exec"))
    if always_shell or (is_subproc and shell_true):
        if tainted_args:
            return ("AS-TS-004", "HIGH", "command")
        # Config-to-command (AS-TS-009): a `command`/`args` value from a server config
        # reaches the same shell sink. argv-list launches never get here (no shell),
        # so the safe, common MCP-launcher pattern does not fire.
        if any(_expr_is_config_cmd(a, cfg_tainted) for a in args):
            return ("AS-TS-009", "HIGH", "config_exec")
    # SSTI: a template BUILT from input (then rendered) is RCE. Only unambiguous
    # server-side-template sinks fire; string.Template ($-substitution) is safe and
    # passing input as data to a fixed template (render(x=...)) is not flagged.
    # `.from_string` is gated on a jinja/template/env receiver so benign constructors
    # (RGBColor.from_string, UUID.from_string, IPv4Address.from_string) do NOT trip.
    recv = (_attr_chain(call.func.value).lower()
            if isinstance(call.func, ast.Attribute) else "")
    is_template_from_string = (
        low.endswith("from_string")
        and any(k in recv for k in ("jinja", "template", "env")))
    if tainted_args and (low.endswith("render_template_string")
                         or is_template_from_string
                         or low == "jinja2.template"):
        return ("AS-TS-007", "HIGH", "ssti")
    # Insecure deserialization: pickle/marshal/dill execute on load unconditionally;
    # yaml.load only when not handed a Safe loader (safe_load / SafeLoader stay silent).
    if tainted_args and low in _DESER_SINKS:
        return ("AS-TS-008", "HIGH", "deser")
    if tainted_args and low in ("yaml.load", "yaml.full_load", "yaml.unsafe_load"):
        loader = kws.get("Loader")
        loader_chain = _attr_chain(loader).lower() if loader is not None else ""
        if "safe" not in loader_chain:
            return ("AS-TS-008", "HIGH", "deser")
    if low.endswith((".execute", ".executemany")):
        # Fire on a query string that is BOTH built by formatting AND carries taint.
        # Inline `execute(f"...{p}...")` is caught directly; the far more common
        # `q = f"...{p}..."; execute(q)` is caught via fmt_tainted (names assigned a
        # formatted+tainted value). A parameterized `execute(sql, (p,))` stays silent:
        # args[0] is a constant, so it is neither formatted nor tainted.
        if args and _expr_tainted(args[0], tainted) and (
                _is_formatted(args[0])
                or (isinstance(args[0], ast.Name) and args[0].id in fmt_tainted)):
            return ("AS-TS-005", "HIGH", "sql")
    is_write_method = (isinstance(call.func, ast.Attribute)
                       and call.func.attr in ("write_text", "write_bytes"))
    if low in _PATH_SINKS or is_write_method:
        path_args = [call.func.value] if is_write_method else args
        if any(_expr_tainted(a, tainted) for a in path_args):
            mutating = low != "open" or is_write_method
            if low == "open":
                mode = (args[1].value if len(args) > 1 and isinstance(args[1], ast.Constant) else "r")
                mutating = any(c in str(mode) for c in "wax+")
            return ("AS-TS-006", "HIGH" if mutating else "MEDIUM", "path")
    if root in _NET_ROOTS and tainted_args:
        return ("AS-TS-003", "MEDIUM", "network")
    return None


def _taint_findings(func, params, rel) -> list[dict]:
    tainted = set(params)
    cfg_tainted: set = set()  # names holding a config-sourced command/args value (AS-TS-009)
    fmt_tainted: set = set()  # names assigned a formatted+tainted string (AS-TS-005 SQLi)
    seen: set[str] = set()
    out: list[dict] = []

    def check(expr_or_stmt):
        for n in ast.walk(expr_or_stmt):
            if not isinstance(n, ast.Call):
                continue
            hit = _classify_sink(n, tainted, cfg_tainted, fmt_tainted)
            if not hit or hit[0] in seen:
                continue
            rule, sev, kind = hit
            seen.add(rule)
            title, why, fix = _SINK_META[kind]
            out.append({
                "rule": rule, "severity": sev, "title": title, "tool": func.name,
                "location": f"{rel}:{getattr(n, 'lineno', func.lineno)}",
                "detail": f"Tool `{func.name}` {why}.", "fix": fix,
            })

    def walk(stmts):
        for stmt in stmts:
            if isinstance(stmt, ast.If) and not stmt.orelse and stmt.body \
                    and isinstance(stmt.body[-1], (ast.Raise, ast.Return)):
                cleared = _validation_clears(stmt.test, tainted)
                if cleared:
                    tainted.difference_update(cleared)
                    continue
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Expr, ast.Return)):
                check(stmt)
            else:
                for fld in ("test", "iter"):
                    if getattr(stmt, fld, None) is not None:
                        check(getattr(stmt, fld))
                for item in getattr(stmt, "items", []):
                    check(item.context_expr)
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                val = stmt.value
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                names = [t.id for t in targets if isinstance(t, ast.Name)]
                if val is not None and _expr_tainted(val, tainted):
                    tainted.update(names)
                elif not isinstance(stmt, ast.AugAssign):
                    tainted.difference_update(names)  # rebind to a clean value clears
                # Propagate config-command taint (AS-TS-009) in parallel.
                if val is not None and _expr_is_config_cmd(val, cfg_tainted):
                    cfg_tainted.update(names)
                elif not isinstance(stmt, ast.AugAssign):
                    cfg_tainted.difference_update(names)
                # Propagate formatted-string taint (AS-TS-005) in parallel: a name
                # bound to an f-string / % / + / .format that carries taint is a
                # SQL-injection candidate once it reaches execute().
                if val is not None and _is_formatted(val) and _expr_tainted(val, tainted):
                    fmt_tainted.update(names)
                elif not isinstance(stmt, ast.AugAssign):
                    fmt_tainted.difference_update(names)
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for fld in ("body", "orelse", "finalbody"):
                    sub = getattr(stmt, fld, None)
                    if isinstance(sub, list):
                        walk(sub)
                for h in getattr(stmt, "handlers", []):
                    walk(h.body)

    walk(func.body)
    return out


# ---------------------------------------------------------------------------
# Low-level server pattern (mcp.server.Server): tools are NOT decorated funcs.
# `@app.list_tools()` returns Tool(name=, description=) declarations; `@app.call_tool()`
# is one async def that dispatches on `name` and reads agent input from `arguments`.
# The decorator loop is blind to both, so most low-level servers report 0 tools.
# We pull the inventory from list_tools and run taint over call_tool with the
# `arguments` mapping as the source, attributing each sink to its `name ==` branch.
# ---------------------------------------------------------------------------

def _is_handler(func, attr: str) -> bool:
    """Is this func decorated with @<x>.<attr>() (e.g. @app.call_tool())?"""
    for d in func.decorator_list:
        target = d.func if isinstance(d, ast.Call) else d
        if isinstance(target, ast.Attribute) and target.attr == attr:
            return True
    return False


def _class_str_attrs(cls) -> dict:
    """String attributes of a class: class-level `name = "x"` and `self.name = "x"`.
    Lets us resolve the common per-tool-class pattern `Tool(name=self.name, ...)`."""
    attrs: dict[str, str] = {}
    for n in ast.walk(cls):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Constant) and isinstance(n.value.value, str):
            for t in n.targets:
                if isinstance(t, ast.Name):
                    attrs[t.id] = n.value.value
                elif isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id == "self":
                    attrs[t.attr] = n.value.value
    return attrs


def _tool_decls(tree, rel) -> list[dict]:
    """`Tool(name=, description=, inputSchema=)` declarations anywhere in the file.
    Low-level servers build these inline in list_tools(), as module-level vars, or
    in per-tool helper classes (`Tool(name=self.name, ...)`). We resolve a `self.X`
    or bare-name `name=` against the enclosing class's string attributes. Requires a
    resolved string name AND a description-or-inputSchema so a stray `Tool(...)` class
    elsewhere is not mistaken for an MCP tool declaration."""
    out: list[dict] = []
    seen_lines: set[int] = set()

    def parse(n, amap):
        if not isinstance(n, ast.Call) or _attr_chain(n.func).split(".")[-1] != "Tool":
            return None

        def as_name(v):
            if isinstance(v, ast.Constant) and isinstance(v.value, str):
                return v.value
            if isinstance(v, ast.Attribute) and isinstance(v.value, ast.Name) and v.value.id == "self":
                return amap.get(v.attr)
            if isinstance(v, ast.Name):
                return amap.get(v.id)
            return None

        name = desc = None
        has_schema = False
        if n.args:
            name = as_name(n.args[0])
        for kw in n.keywords:
            if kw.arg == "name":
                name = as_name(kw.value) or name
            elif kw.arg == "description" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                desc = kw.value.value
            elif kw.arg in ("inputSchema", "input_schema"):
                has_schema = True
        if isinstance(name, str) and name and (desc is not None or has_schema):
            return {"name": name, "description": desc or "", "location": f"{rel}:{n.lineno}"}
        return None

    # Classes first (so `self.X` resolves to the class's literal), then the rest.
    for cls in ast.walk(tree):
        if not isinstance(cls, ast.ClassDef):
            continue
        amap = _class_str_attrs(cls)
        for n in ast.walk(cls):
            if isinstance(n, ast.Call) and n.lineno not in seen_lines:
                t = parse(n, amap)
                if t:
                    out.append(t)
                    seen_lines.add(n.lineno)
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and n.lineno not in seen_lines:
            t = parse(n, {})
            if t:
                out.append(t)
                seen_lines.add(n.lineno)
    return out


def _branch_tool(test):
    """If an `if` test is `name == "X"` (either order), return X, else None."""
    if isinstance(test, ast.Compare) and len(test.ops) == 1 and isinstance(test.ops[0], ast.Eq):
        left, right = test.left, test.comparators[0]
        if isinstance(left, ast.Name) and left.id == "name" and isinstance(right, ast.Constant):
            return right.value
        if isinstance(right, ast.Name) and right.id == "name" and isinstance(left, ast.Constant):
            return left.value
    return None


def _dispatch_taint(func, rel) -> list[dict]:
    """Taint over a call_tool(name, arguments) handler. Every param except the
    `name` selector is agent input; branch context (`if name == "X"`) names the tool.
    Reuses the same sink classifier and source-order propagation as _taint_findings."""
    src = {a.arg for a in func.args.args if a.arg not in ("self", "cls", "name")}
    if not src:
        return []
    out, seen = [], set()

    def check(node, tainted, fmt_tainted, tool):
        for n in ast.walk(node):
            if not isinstance(n, ast.Call):
                continue
            hit = _classify_sink(n, tainted, frozenset(), fmt_tainted)
            if not hit or (hit[0], tool) in seen:
                continue
            rule, sev, kind = hit
            seen.add((rule, tool))
            title, why, fix = _SINK_META[kind]
            out.append({"rule": rule, "severity": sev, "title": title, "tool": tool,
                        "location": f"{rel}:{getattr(n, 'lineno', func.lineno)}",
                        "detail": f"Tool `{tool}` {why}.", "fix": fix})

    def walk(stmts, tainted, fmt_tainted, tool):
        tainted = set(tainted)
        fmt_tainted = set(fmt_tainted)
        for stmt in stmts:
            if isinstance(stmt, ast.If):
                # guard clause `if not valid(x): raise/return` clears x for the rest
                if not stmt.orelse and stmt.body and isinstance(stmt.body[-1], (ast.Raise, ast.Return)):
                    cleared = _validation_clears(stmt.test, tainted)
                    if cleared:
                        tainted -= cleared
                        fmt_tainted -= cleared
                        continue
                check(stmt.test, tainted, fmt_tainted, tool)
                bt = _branch_tool(stmt.test) or tool
                walk(stmt.body, tainted, fmt_tainted, bt)
                walk(stmt.orelse, tainted, fmt_tainted, tool)
                continue
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Expr, ast.Return)):
                check(stmt, tainted, fmt_tainted, tool)
            else:
                for fld in ("test", "iter"):
                    if getattr(stmt, fld, None) is not None:
                        check(getattr(stmt, fld), tainted, fmt_tainted, tool)
                for item in getattr(stmt, "items", []):
                    check(item.context_expr, tainted, fmt_tainted, tool)
            if isinstance(stmt, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                val = stmt.value
                targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                names = [t.id for t in targets if isinstance(t, ast.Name)]
                if val is not None and _expr_tainted(val, tainted):
                    tainted.update(names)
                elif not isinstance(stmt, ast.AugAssign):
                    tainted.difference_update(names)
                if val is not None and _is_formatted(val) and _expr_tainted(val, tainted):
                    fmt_tainted.update(names)
                elif not isinstance(stmt, ast.AugAssign):
                    fmt_tainted.difference_update(names)
            if not isinstance(stmt, (ast.If, ast.FunctionDef, ast.AsyncFunctionDef)):
                for fld in ("body", "orelse", "finalbody"):
                    sub = getattr(stmt, fld, None)
                    if isinstance(sub, list):
                        walk(sub, tainted, fmt_tainted, tool)
                for h in getattr(stmt, "handlers", []):
                    walk(h.body, tainted, fmt_tainted, tool)

    walk(func.body, src, set(), "call_tool")
    return out


# ---------------------------------------------------------------------------
# Core discovery
# ---------------------------------------------------------------------------

def _iter_py_files(root: Path):
    for p in root.rglob("*.py"):
        if _vendored(p):
            continue
        yield p


def _is_non_server_file(rel: str) -> bool:
    """True for test/setup scaffolding that is NOT the running MCP server.

    Codebase-level signals (AS-TR-001 transport) must come from real server code.
    A `transport="streamable-http"` string inside a test fixture or an interactive
    setup/config generator (e.g. setup_mcp.py, test_server.py) is not the server
    actually serving over HTTP, so flagging it is a false positive. Scoped narrowly
    to test_/conftest/setup files on purpose: a real server file is never named
    these, and over-excluding would let a genuine HIGH slip through.
    """
    parts = [seg.lower() for seg in rel.replace("\\", "/").split("/")]
    name = parts[-1]
    if any(seg in ("test", "tests") for seg in parts[:-1]):
        return True
    if name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py":
        return True
    if name == "setup.py" or name.startswith("setup_"):
        return True
    return False


def _iter_config_files(root: Path):
    """Deploy/infra config where real hosts live — scanned for bridge fuel."""
    for p in root.rglob("*"):
        if not p.is_file() or _vendored(p):
            continue
        name = p.name.lower()
        low = str(p).lower()
        is_cfg = (name in _DEPLOY_NAMES or name.endswith(".tf")
                  or name.startswith(".env") or "/.github/workflows/" in low
                  or ("/infrastructure/" in low
                      and (low.endswith((".yaml", ".yml", ".tf", ".json")))))
        if not is_cfg:
            continue
        try:
            if p.stat().st_size > 512_000:
                continue
        except OSError:
            continue
        yield p


def discover(root_path: str) -> dict[str, Any]:
    root = Path(root_path).resolve()
    tools: list[dict[str, Any]] = []
    frameworks: set[str] = set()
    hosts: dict[str, dict] = {}
    findings: list[dict[str, Any]] = []
    files_scanned = 0
    code_flags = {"http_transport": False, "transport_security": False}
    secret_files: list[str] = []

    for py in _iter_py_files(root):
        try:
            src = py.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        files_scanned += 1
        rel = str(py.relative_to(root))

        # candidate hosts (bridge fuel) — classified by source, secrets stripped
        _collect_hosts(src, rel, hosts)

        # codebase-level signals (AS-TR-001 transport, AS-SE-001 secrets).
        # The transport TRIGGER must come from real server code, not a test fixture
        # or setup/config generator; the mitigation (TransportSecuritySettings) is
        # credited from anywhere, so the asymmetry only ever reduces false positives.
        if not _is_non_server_file(rel) and (
                "streamable_http_app" in src or "streamable-http" in src
                or 'transport="sse"' in src or "transport='sse'" in src):
            code_flags["http_transport"] = True
        if "TransportSecuritySettings" in src:
            code_flags["transport_security"] = True
        if "@mcp.tool" in src and _classify_source(rel)[1] != "test" and _SECRET_RE.search(src):
            secret_files.append(rel)

        try:
            tree = ast.parse(src)
        except SyntaxError:
            continue

        for imp in ast.walk(tree):
            if isinstance(imp, ast.ImportFrom) and imp.module:
                for mod, fw in _FRAMEWORK_IMPORTS.items():
                    if imp.module.startswith(mod):
                        frameworks.add(fw)
            elif isinstance(imp, ast.Import):
                for alias in imp.names:
                    for mod, fw in _FRAMEWORK_IMPORTS.items():
                        if alias.name.startswith(mod):
                            frameworks.add(fw)

        # Custom decorators that wrap mcp.tool() (e.g. a conditional-enable @tool).
        wrapper_names = _tool_wrapper_names(tree)

        for node in ast.walk(tree):
            # Tools are overwhelmingly `async def` in real MCP servers; both AST
            # node types carry the same .args/.body/.decorator_list/.name, so the
            # tool helpers below work on either.
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not any(_is_mcp_tool_decorator(d) or _decorator_base_name(d) in wrapper_names
                       for d in node.decorator_list):
                continue

            doc = ast.get_docstring(node) or ""
            caps = _tool_capabilities(node)
            category = _extract_category(node)
            # proxy tools whose client call is indirect still reach the API
            if not caps and category in _API_CATEGORIES:
                caps = {"pinaka-api"}
            name = node.name
            loc = f"{rel}:{node.lineno}"
            action_class = _action_class(name)
            reads_sensitive = bool(_SENS_READ_RE.search(name))
            params = _tool_params(node)
            tool = {
                "name": name,
                "description": doc,
                "category": category,
                "capabilities": sorted(caps),
                "action_class": action_class,
                "reads_sensitive": reads_sensitive,
                "location": loc,
            }
            tools.append(tool)

            # --- finding rules (precise, first-party-aware) ---
            # Intra-procedural taint: param -> sink (AS-TS-004/005/006, deepened 003).
            # A precise taint hit subsumes the coarse presence rules below.
            taint_results = _taint_findings(node, params, rel)
            taint_rules = {f["rule"] for f in taint_results}

            m = _IMPERATIVE_RE.search(doc) or _DIRECTIVE_RE.search(doc)
            if m:
                findings.append({
                    "rule": "AS-GI-001",
                    "severity": "MEDIUM",
                    "title": "Imperative language in MCP tool description",
                    "tool": node.name,
                    "location": f"{rel}:{node.lineno}",
                    "detail": f'Description contains "{m.group(0)}" — instruction-like '
                              "text in a tool description is a prompt-injection surface.",
                    "fix": "Describe functionality only; move agent guidance into prompts.",
                })
            if "exec" in caps and "AS-TS-004" not in taint_rules:
                findings.append({
                    "rule": "AS-TS-001",
                    "severity": "HIGH",
                    "title": "MCP tool can execute shell/eval",
                    "tool": node.name,
                    "location": f"{rel}:{node.lineno}",
                    "detail": "Tool body reaches a process-exec / eval sink — high blast "
                              "radius if the agent is steered into calling it.",
                    "fix": "Gate behind explicit allow-list; never pass model text to a shell.",
                })
            if "filesystem" in caps and "pinaka-api" not in caps and "AS-TS-006" not in taint_rules:
                findings.append({
                    "rule": "AS-TS-002",
                    "severity": "LOW",
                    "title": "MCP tool has direct filesystem access",
                    "tool": name,
                    "location": loc,
                    "detail": "Tool touches the filesystem outside the authed API client.",
                    "fix": "Confirm path inputs are validated and scoped.",
                })
            pm = _POISON_RE.search(doc)
            if pm:
                findings.append({
                    "rule": "AS-GI-002",
                    "severity": "HIGH",
                    "title": "Hidden/injection markers in MCP tool description",
                    "tool": name,
                    "location": loc,
                    "detail": f'Description contains "{pm.group(0).strip()}" — a tool-poisoning '
                              "marker that can hijack the agent before the tool is even called.",
                    "fix": "Remove hidden instructions, HTML/comment markers, and file-path lures.",
                })
            hu = _hidden_char_finding(name, loc, doc)
            if hu:
                findings.append(hu)
            if action_class in ("destructive", "external_send"):
                act = ("performs a destructive action" if action_class == "destructive"
                       else "sends data to an external system")
                findings.append({
                    "rule": "AS-EA-001",
                    "severity": "MEDIUM",
                    "title": "Side-effecting tool without an explicit consent gate",
                    "tool": name,
                    "location": loc,
                    "detail": f"Tool `{name}` {act}. High-agency tools should carry a "
                              "destructive/confirmation hint so the agent can't trigger them silently.",
                    "fix": "Add a human-confirmation / destructiveHint gate before the side effect.",
                })
            if action_class == "credential" or any(p in ("cookies", "headers", "token", "auth", "value") for p in params) and _CRED_RE.search(name):
                findings.append({
                    "rule": "AS-IA-001",
                    "severity": "MEDIUM",
                    "title": "MCP tool handles credential material",
                    "tool": name,
                    "location": loc,
                    "detail": f"Tool `{name}` accepts/stores auth material (cookies/headers/tokens). "
                              "Ensure it's audience-scoped, never logged, and cleared with the session.",
                    "fix": "Scope and short-TTL stored credentials; never forward tokens upstream un-scoped.",
                })
            # Precise taint findings (AS-TS-004/005/006 + deepened AS-TS-003) replace
            # the old coarse "any param + any sink + no validate" heuristic.
            findings.extend(taint_results)

        # Low-level Server() pattern: Tool(...) declarations + call_tool() dispatch.
        # Invisible to the decorator loop above, so scan for it explicitly. Gate the
        # file-wide Tool() scan on an MCP signal so a stray Tool class is not picked up,
        # and skip test scaffolding.
        is_mcp_file = any(s in src for s in ("list_tools", "call_tool", "mcp.server",
                                             "mcp.types", "from mcp", "import mcp"))
        if is_mcp_file and _classify_source(rel)[1] != "test":
            for t in _tool_decls(tree, rel):
                if not any(x["name"] == t["name"] for x in tools):
                    name, doc, loc = t["name"], t["description"], t["location"]
                    action_class = _action_class(name)
                    tools.append({
                        "name": name, "description": doc, "category": None,
                        "capabilities": [], "action_class": action_class,
                        "reads_sensitive": bool(_SENS_READ_RE.search(name)),
                        "location": loc,
                    })
                    m = _IMPERATIVE_RE.search(doc) or _DIRECTIVE_RE.search(doc)
                    if m:
                        findings.append({
                            "rule": "AS-GI-001", "severity": "MEDIUM",
                            "title": "Imperative language in MCP tool description",
                            "tool": name, "location": loc,
                            "detail": f'Description contains "{m.group(0)}" — instruction-like '
                                      "text in a tool description is a prompt-injection surface.",
                            "fix": "Describe functionality only; move agent guidance into prompts.",
                        })
                    pm = _POISON_RE.search(doc)
                    if pm:
                        findings.append({
                            "rule": "AS-GI-002", "severity": "HIGH",
                            "title": "Hidden/injection markers in MCP tool description",
                            "tool": name, "location": loc,
                            "detail": f'Description contains "{pm.group(0).strip()}" — a tool-poisoning '
                                      "marker that can hijack the agent before the tool is even called.",
                            "fix": "Remove hidden instructions, HTML/comment markers, and file-path lures.",
                        })
                    hu = _hidden_char_finding(name, loc, doc)
                    if hu:
                        findings.append(hu)
                    if action_class in ("destructive", "external_send"):
                        act = ("performs a destructive action" if action_class == "destructive"
                               else "sends data to an external system")
                        findings.append({
                            "rule": "AS-EA-001", "severity": "MEDIUM",
                            "title": "Side-effecting tool without an explicit consent gate",
                            "tool": name, "location": loc,
                            "detail": f"Tool `{name}` {act}. High-agency tools should carry a "
                                      "destructive/confirmation hint so the agent can't trigger them silently.",
                            "fix": "Add a human-confirmation / destructiveHint gate before the side effect.",
                        })
            for fn in ast.walk(tree):
                if isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)) and _is_handler(fn, "call_tool"):
                    findings.extend(_dispatch_taint(fn, rel))

    # Second pass: deploy/infra config — where real "this runs here" hosts live.
    for cfg in _iter_config_files(root):
        try:
            text = cfg.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        files_scanned += 1
        _collect_hosts(text, str(cfg.relative_to(root)), hosts)

    # --- codebase / server-level rules ---
    for rel in sorted(set(secret_files)):
        findings.append({
            "rule": "AS-SE-001", "severity": "HIGH",
            "title": "Hardcoded secret in MCP tool/server code",
            "tool": "(server)", "location": rel,
            "detail": "A credential-shaped literal (API key / token / PEM) appears in a "
                      "file that defines MCP tools.",
            "fix": "Move secrets to env/secret-manager; rotate any that were committed.",
        })
    if code_flags["http_transport"] and not code_flags["transport_security"]:
        findings.append({
            "rule": "AS-TR-001", "severity": "HIGH",
            "title": "MCP HTTP/SSE transport without DNS-rebinding/Origin protection",
            "tool": "(server)", "location": ".",
            "detail": "Streamable-HTTP/SSE transport is used with no TransportSecuritySettings — "
                      "the class of issue behind CVE-2025-66416 (DNS-rebinding to local tools).",
            "fix": "Configure TransportSecuritySettings (allowed Hosts/Origins) on the MCP app.",
        })
    if any(t.get("reads_sensitive") for t in tools) and any(t.get("action_class") == "external_send" for t in tools):
        readers = [t["name"] for t in tools if t.get("reads_sensitive")][:3]
        senders = [t["name"] for t in tools if t.get("action_class") == "external_send"][:3]
        findings.append({
            "rule": "AS-DL-001", "severity": "HIGH",
            "title": "Lethal trifecta: server reads sensitive data and can send externally",
            "tool": "(server)", "location": ".",
            "detail": f"Sensitive readers ({', '.join(readers)}) coexist with external senders "
                      f"({', '.join(senders)}) — a structural data-exfiltration channel an "
                      "injection could ride.",
            "fix": "Separate privilege domains, or gate the send path behind explicit human consent.",
        })

    # --- Claude Skill (SKILL.md) ingestion — gated on SKILL.md presence ---
    # Description rules run on the SKILL.md text; bundled plain functions are
    # taint-scanned exactly like tools. Findings carry skill/surface attribution
    # and go into the shared `findings` list (so standards mapping + the UI work
    # unchanged); bundled functions stay OUT of `tools` and the graph.
    skills: list[dict[str, Any]] = []
    inventoried = {t["name"] for t in tools}
    for skill_md in _iter_skill_dirs(root):
        try:
            text = skill_md.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        files_scanned += 1  # SKILL.md isn't a .py, so not otherwise counted
        meta, body = _parse_frontmatter(text)
        rel_md = str(skill_md.relative_to(root))
        sk_name = meta.get("name") or skill_md.parent.name
        desc = meta.get("description", "")
        sk_findings = _skill_description_findings(sk_name, rel_md, desc + "\n" + body)
        tool_names: list[str] = []
        for py in sorted(skill_md.parent.glob("*.py")):
            if _vendored(py):
                continue
            try:
                tree = ast.parse(py.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, SyntaxError):
                continue
            rel_py = str(py.relative_to(root))
            for fn in _skill_tool_functions(tree):
                if fn.name in inventoried:
                    continue  # already a real @mcp.tool — don't double-scan as a skill fn
                tool_names.append(fn.name)
                for f in _taint_findings(fn, _tool_params(fn), rel_py):
                    f["skill"] = sk_name
                    f["surface"] = "skill"
                    sk_findings.append(f)
        findings.extend(sk_findings)
        skills.append({
            "name": sk_name,
            "description": desc,
            "location": rel_md,
            "tools": tool_names,
            "findings": len(sk_findings),
        })

    # attach standard mappings to every finding
    for f in findings:
        f["standards"] = _STANDARDS.get(f["rule"], [])

    candidate_hosts = [
        {"host": h, **meta}
        for h, meta in sorted(
            hosts.items(),
            key=lambda kv: (-_CONF_RANK[kv[1]["confidence"]], kv[0]),
        )
    ]
    bridge_candidates = sum(1 for c in candidate_hosts if c["kind"] == "deploy")

    nodes, edges = _build_graph(frameworks, tools)
    return {
        "root": str(root),
        "frameworks": sorted(frameworks),
        "stats": {
            "files_scanned": files_scanned,
            "tools": len(tools),
            "skills": len(skills),
            "candidate_hosts": len(candidate_hosts),
            "bridge_candidates": bridge_candidates,
            "findings": len(findings),
        },
        "tools": tools,
        "skills": skills,
        "candidate_hosts": candidate_hosts,
        "nodes": nodes,
        "edges": edges,
        "findings": findings,
    }


def _build_graph(frameworks: set[str], tools: list[dict]) -> tuple[list, list]:
    nodes: list[dict] = []
    edges: list[dict] = []
    server_id = "mcp_server:local"
    if frameworks:
        nodes.append({"id": server_id, "type": "mcp_server",
                      "label": "/".join(sorted(frameworks)) + " server"})
    cap_targets = {
        "pinaka-api": ("external:pinaka-api", "external", "Pinaka API"),
        "exec": ("data_system:shell", "data_system", "shell / exec"),
        "filesystem": ("data_system:filesystem", "data_system", "filesystem"),
        "network": ("external:network", "external", "outbound network"),
        "cloud": ("external:cloud", "external", "cloud SDK"),
        "database": ("data_system:db", "data_system", "database"),
    }
    seen: set[str] = set()
    for t in tools:
        tid = f"tool:{t['name']}"
        nodes.append({"id": tid, "type": "tool", "label": t["name"],
                      "meta": {"category": t["category"]}})
        if frameworks:
            edges.append({"source": server_id, "target": tid, "type": "exposes"})
        for cap in t["capabilities"]:
            if cap in cap_targets:
                cid, ctype, clabel = cap_targets[cap]
                if cid not in seen:
                    nodes.append({"id": cid, "type": ctype, "label": clabel})
                    seen.add(cid)
                edges.append({"source": tid, "target": cid, "type": "reaches"})
    return nodes, edges


def redact(graph: dict[str, Any]) -> dict[str, Any]:
    """Upload-safe view: strip secret-looking tokens from any free text, keep
    structure + hostnames intact.

    Hostnames are the user's OWN infra (same-tenant, like resolved_subdomains)
    and the cross-surface bridge needs them real to match — so they stay.
    Secrets are the only thing that must never leave the machine. Cross-TENANT
    redaction (hostnames → patterns) happens later, server-side, before anything
    enters the shared memory/embedding plane.
    """
    out = json.loads(json.dumps(graph))
    for t in out.get("tools", []):
        if t.get("description"):
            t["description"] = _SECRET_RE.sub("<REDACTED>", t["description"])
    for f in out.get("findings", []):
        if f.get("detail"):
            f["detail"] = _SECRET_RE.sub("<REDACTED>", f["detail"])
    return out


# ---------------------------------------------------------------------------
# Formatting
# ---------------------------------------------------------------------------

_SEV_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
_SEV_BADGE = {"HIGH": "🟠 HIGH", "MEDIUM": "🟡 MEDIUM", "LOW": "🔵 LOW"}


def format_summary(g: dict[str, Any]) -> str:
    s = g["stats"]
    lines = [
        "# Agent Surface — Discovery",
        f"**Root:** `{g['root']}`",
        f"**Framework:** {', '.join(g['frameworks']) or 'none detected'}",
        f"**Files scanned:** {s['files_scanned']}  ·  "
        f"**Tools:** {s['tools']}  ·  "
        f"**Hosts:** {s['candidate_hosts']} ({s.get('bridge_candidates', 0)} deploy)  ·  "
        f"**Findings:** {s['findings']}",
        "",
        "## Findings",
    ]
    if not g["findings"]:
        lines.append("_No findings._")
    else:
        for f in sorted(g["findings"], key=lambda x: _SEV_ORDER.get(x["severity"], 9)):
            lines.append(f"\n**{_SEV_BADGE.get(f['severity'], f['severity'])}  "
                         f"{f['title']}** [{f['rule']}]")
            lines.append(f"  - tool `{f['tool']}` — `{f['location']}`")
            lines.append(f"  - {f['detail']}")
            if f.get("standards"):
                lines.append(f"  - _maps to:_ {', '.join(f['standards'])}")
            lines.append(f"  - _fix:_ {f['fix']}")

    by_cat: dict[str, int] = defaultdict(int)
    for t in g["tools"]:
        by_cat[t["category"] or "uncategorized"] += 1
    lines.append("\n## Tools by category")
    for cat, n in sorted(by_cat.items(), key=lambda x: -x[1]):
        lines.append(f"  - {cat}: {n}")

    if g["candidate_hosts"]:
        deploy = [c for c in g["candidate_hosts"] if c["kind"] == "deploy"]
        integ = [c for c in g["candidate_hosts"] if c["kind"] == "integration"]
        test = [c for c in g["candidate_hosts"] if c["kind"] == "test"]
        lines.append("\n## Bridge candidates (deploy hosts → match vs resolved_subdomains)")
        if deploy:
            for c in deploy[:20]:
                lines.append(f"  - `{c['host']}`  _({c['confidence']}, {c['source']})_")
        else:
            lines.append("  _none — no hosts in deploy/infra config_")
        lines.append(f"\n_Also: {len(integ)} third-party integration host(s), "
                     f"{len(test)} test/payload host(s) excluded from bridge._")
    return "\n".join(lines)


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "."
    result = discover(path)
    if "--json" in sys.argv:
        print(json.dumps(result, indent=2))
    else:
        print(format_summary(result))
