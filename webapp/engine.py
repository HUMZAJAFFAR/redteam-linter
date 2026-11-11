"""Embedded scan engine for the RedTeam Linter web console.

The CLI pipeline (``harvester.py`` + ``analyzer.py``) is the production engine,
but it is file-system oriented: it walks a directory and prints to a terminal.
The web console needs to scan *pasted or uploaded* sources and hand a clean list
of findings to :class:`reporter.ReportGenerator`.

This module is that in-memory adapter plus a small, dependency-free heuristic
engine so the UI is fully functional standalone:

*   **Sinks** come from ``config_loader.load_sink_config`` (YAML, with the
    built-in fallback), so the console and the CLI are always driven by the same
    rule set.
*   **Secrets** use a compact pattern set modelled on the harvester.

Findings are emitted in the canonical schema consumed by ``reporter.py``:
``file_path``, ``line_number``, ``severity``, ``category``, ``sink``,
``matched_snippet``, ``secret_value``, ``arguments_passed`` and ``description``.

Security note: findings returned by :func:`scan_files` still contain **raw**
snippets and secret values.  They must always be routed through
``ReportGenerator.build_payload()`` (or ``export_to_json``) before leaving the
process, which is exactly what ``server.py`` does.  ``arguments_passed`` is the
taint-tracing bridge and is kept structurally intact, but any string literal
that itself matches a credential pattern is masked here so that a secret cannot
sneak into the UI through a call argument.
"""

from __future__ import annotations

import ast
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# Severity model
# ---------------------------------------------------------------------------

SEVERITY_LADDER: Tuple[str, ...] = ("INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL")

#: Default severity per sink name.  YAML rules may override it with a
#: ``severity`` key.
SEVERITY_BY_SINK: Dict[str, str] = {
    "eval": "CRITICAL",
    "exec": "CRITICAL",
    "pickle.loads": "CRITICAL",
    "os.system": "HIGH",
    "os.popen": "HIGH",
    "compile": "MEDIUM",
    "subprocess.call": "MEDIUM",
}

CATEGORY_NOTES: Dict[str, str] = {
    "RCE": "Remote code execution sink: attacker-controlled input here means code execution.",
    "DESERIALIZATION": "Unsafe deserialization: a crafted payload can execute arbitrary code.",
    "COMMAND_INJECTION": "Shell metacharacters in the argument can chain extra commands.",
    "SQLI": "Unparameterised SQL built from a string.",
}

#: Calls/attributes considered attacker-controlled input sources.
_TAINT_FUNCS: Set[str] = {
    "input",
    "raw_input",
    "os.getenv",
    "os.environ.get",
    "os.environ.setdefault",
    "sys.stdin.read",
}

_TAINT_PREFIXES: Tuple[str, ...] = (
    "request.",
    "self.request.",
    "flask.request.",
    "request.form",
    "request.args",
    "request.json",
    "request.values",
)

_TAINT_ATTR_ROOTS: Tuple[str, ...] = ("sys.argv", "os.environ", "request.form", "request.args")


# ---------------------------------------------------------------------------
# Secret patterns (harvester equivalent)
# ---------------------------------------------------------------------------

_SECRET_PLACEHOLDERS = {
    "",
    "changeme",
    "change_me",
    "password",
    "secret",
    "token",
    "your_key_here",
    "your-key-here",
    "example",
    "xxx",
    "xxxx",
    "test",
    "dummy",
    "none",
    "null",
}

SECRET_PATTERNS: Sequence[Dict[str, Any]] = (
    {
        "rule_id": "aws-access-key",
        "label": "AWS access key id",
        "severity": "HIGH",
        "regex": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    },
    {
        "rule_id": "github-token",
        "label": "GitHub token",
        "severity": "HIGH",
        "regex": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"),
    },
    {
        "rule_id": "slack-token",
        "label": "Slack token",
        "severity": "HIGH",
        "regex": re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b"),
    },
    {
        "rule_id": "private-key",
        "label": "Private key block",
        "severity": "HIGH",
        "regex": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    },
    {
        "rule_id": "jwt",
        "label": "JSON Web Token",
        "severity": "MEDIUM",
        "regex": re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
    },
    {
        "rule_id": "bearer-token",
        "label": "Bearer token",
        "severity": "MEDIUM",
        "regex": re.compile(r"(?i)\bbearer\s+([A-Za-z0-9\-._~+/]{16,}=*)"),
    },
    {
        "rule_id": "generic-credential",
        "label": "Hardcoded credential",
        "severity": "MEDIUM",
        # ``(?<![A-Za-z0-9])`` instead of ``\b`` so DB_PASSWORD and
        # MY_API_KEY still match: ``_`` is a word character, so a plain word
        # boundary would reject them.
        "regex": re.compile(
            r"(?i)(?<![A-Za-z0-9])(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token"
            r"|token|password|passwd|pwd)(?![A-Za-z0-9])\s*[=:]\s*['\"]([^'\"\s]{8,})['\"]"
        ),
    },
)


def _looks_like_placeholder(value: str) -> bool:
    """Filter out template values so the console is not drowned in noise."""
    probe = value.strip().strip("'\"").lower()
    if probe in _SECRET_PLACEHOLDERS:
        return True
    return any(token in probe for token in ("{{", "}}", "<", "your_", "example."))


def _matched_value(match: "re.Match[str]") -> str:
    """Return the credential portion of a match (group 1/2 when present)."""
    if match.re.groups:
        for group in range(match.re.groups, 0, -1):
            candidate = match.group(group)
            if candidate:
                return candidate
    return match.group(0)


def scan_secrets(source: str) -> List[Dict[str, Any]]:
    """Find credential-looking strings in ``source``, one finding per line.

    When a line matches several patterns the highest-severity match wins, which
    keeps the report readable without weakening detection.
    """
    severity_rank = {name: index for index, name in enumerate(SEVERITY_LADDER)}
    best_per_line: Dict[int, Dict[str, Any]] = {}
    source_lines = source.splitlines()

    for lineno, raw_line in enumerate(source_lines, start=1):
        line = raw_line.rstrip("\n")
        for pattern in SECRET_PATTERNS:
            for match in pattern["regex"].finditer(line):
                value = _matched_value(match)
                if _looks_like_placeholder(value):
                    continue
                candidate: Dict[str, Any] = {
                    "file_path": "",  # filled in by scan_files
                    "line_number": lineno,
                    "severity": pattern["severity"],
                    "category": "SECRET",
                    "sink": pattern["rule_id"],
                    "rule_id": pattern["rule_id"],
                    "matched_snippet": line.strip(),
                    "secret_value": value,
                    "arguments_passed": [],
                    "description": (
                        f"{pattern['label']} hardcoded in source. Rotate the credential and "
                        "move it to a secret store."
                    ),
                    "source_context": source_excerpt(source_lines, lineno),
                }
                current = best_per_line.get(lineno)
                if current is None or severity_rank[candidate["severity"]] > severity_rank[
                    current["severity"]
                ]:
                    best_per_line[lineno] = candidate
                break  # one finding per pattern per line is enough

    return [best_per_line[line] for line in sorted(best_per_line)]


def mask_secrets_in_text(text: str) -> str:
    """Best-effort masking used on ``arguments_passed`` and source excerpts.

    Only the credential *value* is replaced, never the whole match, so masking
    ``GITHUB_TOKEN = "ghp_..."`` keeps the key name readable instead of
    collapsing the line to ``GITHUB_<redacted>``.
    """
    for pattern in SECRET_PATTERNS:
        regex = pattern["regex"]

        def replace(match: "re.Match[str]", regex: "re.Pattern[str]" = regex) -> str:
            if not regex.groups:
                return "<redacted>"
            index = match.lastindex or regex.groups
            start, end = match.span(index)
            whole = match.group(0)
            head = whole[: start - match.start()]
            tail = whole[end - match.start() :]
            return f"{head}<redacted>{tail}"

        text = regex.sub(replace, text)
    return text


def _mask_assignment(match: "re.Match[str]") -> str:
    """Replace the literal in ``PASSWORD = "..."``, leaving the name intact."""
    value = match.group("value")
    if value.startswith("<") or "REDACTED" in value.upper():
        return match.group(0)
    return "{key}{quote}<redacted>{quote}".format(
        key=match.group("key"), quote=match.group("quote")
    )


_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?i)(?P<key>(?:api[_-]?key|secret|token|password|passwd|pwd)[A-Za-z0-9_]*\s*[=:]\s*)"
    r"(?P<quote>['\"])(?P<value>[^'\"\s]{6,})(?P=quote)"
)


def scrub_source_line(text: str) -> str:
    """Mask credential material inside one source line, keeping its structure.

    The console renders a redacted excerpt around each finding.  Masking the
    *value* instead of the whole line keeps ``DB_PASSWORD = "<redacted>"``
    readable without shipping the secret to the browser.
    """
    scrubbed = mask_secrets_in_text(text)
    scrubbed = _SENSITIVE_ASSIGNMENT.sub(_mask_assignment, scrubbed)
    return scrubbed.expandtabs(2).rstrip()[:200]


def source_excerpt(
    lines: Sequence[str], line_number: int, radius: int = 2
) -> List[Dict[str, Any]]:
    """Return a redacted context window around ``line_number`` (1-indexed)."""
    if not lines or line_number < 1:
        return []
    start = max(1, line_number - radius)
    end = min(len(lines), line_number + radius)
    return [
        {
            "line": number,
            "text": scrub_source_line(lines[number - 1]),
            "target": number == line_number,
        }
        for number in range(start, end + 1)
    ]


# ---------------------------------------------------------------------------
# AST helpers
# ---------------------------------------------------------------------------


def _dotted_name(node: Optional[ast.AST]) -> Optional[str]:
    """Render ``a.b.c`` for an Attribute/Name chain, else ``None``."""
    parts: List[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return None


def _collect_aliases(tree: ast.AST) -> Dict[str, str]:
    """Map local names to fully qualified callables.

    Handles ``import subprocess as sp``, ``from os import system`` and
    ``from os import system as sh`` so YAML rules stay written against the
    canonical dotted name.
    """
    aliases: Dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.asname:
                    aliases[alias.asname] = alias.name
                else:
                    root = alias.name.split(".")[0]
                    aliases[root] = root
        elif isinstance(node, ast.ImportFrom) and node.module:
            for alias in node.names:
                local = alias.asname or alias.name
                aliases[local] = f"{node.module}.{alias.name}"
    return aliases


def _resolve_call_name(func: ast.AST, aliases: Dict[str, str]) -> Optional[str]:
    """Resolve a call target to its canonical dotted name."""
    name = _dotted_name(func)
    if not name:
        return None
    root, _, rest = name.partition(".")
    resolved_root = aliases.get(root)
    if resolved_root is None:
        return name
    return f"{resolved_root}.{rest}" if rest else resolved_root


def _is_taint_source(node: ast.AST) -> bool:
    """True when ``node`` reads from a classic attacker-controlled source."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            dotted = _dotted_name(child.func) or ""
            if dotted in _TAINT_FUNCS or dotted.startswith(_TAINT_PREFIXES):
                return True
        elif isinstance(child, (ast.Attribute, ast.Subscript)):
            dotted = _dotted_name(child)
            if dotted and any(dotted.startswith(root) for root in _TAINT_ATTR_ROOTS):
                return True
    return False


def _collect_tainted_names(tree: ast.AST) -> Set[str]:
    """Track simple ``x = <user input>`` assignments (two fixpoint passes)."""
    tainted: Set[str] = set()
    for _ in range(2):
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and _is_taint_source(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        tainted.add(target.id)
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        for element in target.elts:
                            if isinstance(element, ast.Name):
                                tainted.add(element.id)
            elif (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"get", "getlist", "pop"}
                and _is_taint_source(node.func.value)
            ):
                for parent in ast.walk(tree):
                    if isinstance(parent, ast.Assign) and parent.value is node:
                        for target in parent.targets:
                            if isinstance(target, ast.Name):
                                tainted.add(target.id)
    return tainted


def _argument_text(node: ast.AST, source: str) -> str:
    """Render a single call argument, truncated and secret-masked."""
    try:
        text = ast.unparse(node)  # Python 3.9+
    except Exception:  # pragma: no cover - ast.unparse is very reliable
        text = ast.get_source_segment(source, node) or "<expression>"
    text = " ".join(text.split())
    if len(text) > 160:
        text = text[:157] + "..."
    return mask_secrets_in_text(text)


def _severity_for(
    sink_name: str, rule: Dict[str, Any], shell_true: bool, tainted: bool, literal_only: bool
) -> str:
    """Derive a severity from the rule, shell usage, taint and literal-ness."""
    declared = str(rule.get("severity") or SEVERITY_BY_SINK.get(sink_name, "MEDIUM")).upper()
    if declared not in SEVERITY_LADDER:
        declared = "MEDIUM"

    index = SEVERITY_LADDER.index(declared)
    if tainted:
        index = len(SEVERITY_LADDER) - 1  # confirmed user input -> CRITICAL
    elif shell_true and bool(rule.get("requires_shell_true")):
        index = min(index + 1, len(SEVERITY_LADDER) - 1)
    elif literal_only:
        index = max(index - 1, 0)
    return SEVERITY_LADDER[index]


def scan_python(source: str, file_path: str, rules: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Scan one Python source string for sink calls and hardcoded secrets.

    Parameters
    ----------
    source:
        Raw Python source.
    file_path:
        Logical path recorded in each finding.
    rules:
        Sink rules from :func:`config_loader.load_sink_config`.
    """
    findings: List[Dict[str, Any]] = []

    try:
        tree = ast.parse(source, filename=file_path)
    except SyntaxError as exc:
        return [
            {
                "file_path": file_path,
                "line_number": int(exc.lineno or 0),
                "severity": "INFO",
                "category": "PARSE_ERROR",
                "sink": "ast.parse",
                "rule_id": "parse-error",
                "matched_snippet": (exc.text or "").strip(),
                "secret_value": "",
                "arguments_passed": [],
                "description": f"File skipped: {exc.msg}.",
                "source_context": source_excerpt(
                    source.splitlines(), int(exc.lineno or 0)
                ),
            }
        ]

    aliases = _collect_aliases(tree)
    tainted_names = _collect_tainted_names(tree)
    lines = source.splitlines()
    rule_by_name = {str(rule.get("name")): rule for rule in rules}

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        resolved = _resolve_call_name(node.func, aliases)
        if not resolved:
            continue

        rule = rule_by_name.get(resolved)
        if rule is None:
            # Also match a rule written against an alias-free import name.
            rule = rule_by_name.get(resolved.split(".")[-1])
            if rule is None:
                continue

        shell_true = any(
            isinstance(keyword.value, ast.Constant) and keyword.value.value is True
            and keyword.arg == "shell"
            for keyword in node.keywords
        )

        tainted = any(_is_taint_source(arg) for arg in node.args) or any(
            isinstance(arg, ast.Name) and arg.id in tainted_names for arg in node.args
        )
        literal_only = bool(node.args) and all(
            isinstance(arg, ast.Constant) for arg in node.args
        )

        arguments = [_argument_text(arg, source) for arg in node.args]
        arguments += [
            f"{keyword.arg}={_argument_text(keyword.value, source)}"
            for keyword in node.keywords
            if keyword.arg
        ]

        severity = _severity_for(str(rule.get("name")), rule, shell_true, tainted, literal_only)
        category = str(rule.get("category") or "UNKNOWN").upper()
        snippet = (lines[node.lineno - 1].strip() if node.lineno - 1 < len(lines) else "")[:300]

        notes = [CATEGORY_NOTES.get(category, rule.get("description") or "Dangerous callable invoked.")]
        if shell_true:
            notes.append("shell=True hands the string to /bin/sh.")
        if tainted:
            notes.append("Argument traces back to user-controlled input (heuristic).")
        if literal_only:
            notes.append("Only literal arguments detected — lower immediate risk.")

        findings.append(
            {
                "file_path": file_path,
                "line_number": int(node.lineno),
                "col_offset": int(node.col_offset),
                "severity": severity,
                "category": category,
                "sink": resolved,
                "rule_id": str(rule.get("name")),
                "matched_snippet": snippet,
                "secret_value": "",
                "arguments_passed": arguments,
                "user_input_reachable": tainted,
                "requires_shell_true": bool(rule.get("requires_shell_true")),
                "shell_true_present": shell_true,
                "description": " ".join(notes),
                "source_context": source_excerpt(lines, int(node.lineno)),
            }
        )

    for secret in scan_secrets(source):
        secret["file_path"] = file_path
        findings.append(secret)

    return findings


def scan_files(
    files: Sequence[Dict[str, str]], rules: Sequence[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[str], List[str]]:
    """Scan several ``{"path", "content"}`` documents.

    Returns ``(findings, scanned_paths, skipped_paths)``.  Non-Python documents
    are skipped rather than rejected so a mixed upload still produces a report.
    """
    findings: List[Dict[str, Any]] = []
    scanned: List[str] = []
    skipped: List[str] = []

    for document in files:
        path = document.get("path") or "untitled.py"
        content = document.get("content") or ""
        if not path.endswith(".py"):
            skipped.append(path)
            continue
        findings.extend(scan_python(content, path, rules))
        scanned.append(path)

    return findings, scanned, skipped
